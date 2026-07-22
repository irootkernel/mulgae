package rerun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"

	appprompt "github.com/irootkernel/kkachi-agent-review/internal/app/prompt"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	rerunSession   = "s_019f596a-cf80-7c67-b265-f37053d51ccf"
	rerunSourceRun = "r_019f596a-cf80-7c67-b265-f37053d51ccf"
	rerunChildRun  = "r_019f596a-cf81-7c67-b265-f37053d51ccf"
	rerunReview    = "019f596a-cf80-7c67-b265-f37053d51ccf"
	rerunAttempt   = "a_019f596a-cf80-7c67-b265-f37053d51ccf"
)

type rerunSourceReader struct {
	source        SourceAttempt
	observed      *SourceAttempt
	err           error
	calls         int
	requireActive bool
}

func (reader *rerunSourceReader) ReadRerunSource(ctx context.Context, _ domain.RunID, _ domain.AttemptID) (SourceAttempt, error) {
	reader.calls++
	if reader.requireActive && ctx.Err() != nil {
		return SourceAttempt{}, ctx.Err()
	}
	if reader.calls > 1 && reader.observed != nil {
		return *reader.observed, reader.err
	}
	return reader.source, reader.err
}

type rerunExecutor struct {
	child    ChildReplay
	calls    int
	resultID domain.RunID
	cancel   func()
	result   *ChildReplayResult
	exitCode domain.OperationalExitCode
}

func (executor *rerunExecutor) ExecuteChildReplay(_ context.Context, child ChildReplay) (ChildReplayResult, error) {
	executor.calls++
	executor.child = cloneChildReplay(child)
	child.Target.Bytes[0] = 'X'
	if child.Exact != nil {
		child.Exact.ComposedStdin[0] = 'X'
		child.Exact.Parameters[0].Value = "changed"
	}
	if executor.cancel != nil {
		executor.cancel()
	}
	if executor.result != nil {
		return *executor.result, nil
	}
	return mustChildReplayResult(child, executor.resultID, executor.exitCode), nil
}

func TestStartRerunExactCopiesImmutableSource(t *testing.T) {
	source := validRerunSource()
	before := cloneRerunSource(source)
	reader := &rerunSourceReader{source: source}
	executor := &rerunExecutor{}
	service := testRerunService(t, reader, executor)
	result, err := service.StartRerun(context.Background(), Request{SourceRunID: source.RunID, SourceAttemptID: source.AttemptID, ReplayMode: ExactReplay})
	if err != nil {
		t.Fatal(err)
	}
	if result.RunID != mustRerunRun(rerunChildRun) || executor.child.Run.ID() != result.RunID || result.SessionID != source.SessionID || executor.child.Mode != ExactReplay || executor.child.Exact == nil {
		t.Fatalf("unexpected exact result or child: %#v %#v", result, executor.child)
	}
	if roles := executor.child.Run.RoleTasks(); len(roles) != 1 ||
		roles[0].Role() != domain.RoleSecurity ||
		executor.child.Role != string(domain.RoleSecurity) {
		t.Fatalf("exact replay authority = roles %#v, selected %q; want one selected security role", roles, executor.child.Role)
	}
	if assignments := executor.child.Assignments; len(assignments) != 1 || assignments[0].Role() != domain.RoleSecurity {
		t.Fatalf("exact assignments = %#v, want one security assignment", assignments)
	}
	if !reflect.DeepEqual(source, before) {
		t.Fatalf("source changed: got %#v want %#v", source, before)
	}
	if !reflect.DeepEqual(reader.source, before) {
		t.Fatal("reader source bytes changed through child input")
	}
	if rerunDigest(source.Target.Bytes) != before.Target.SHA256 || rerunDigest(source.Prompt.ComposedStdin) != before.Prompt.ComposedStdinSHA256 {
		t.Fatal("source byte hashes changed")
	}
	if got := executor.child.Exact; !reflect.DeepEqual(got.Parameters, before.Prompt.Parameters) || string(got.ComposedStdin) != string(before.Prompt.ComposedStdin) || got.SourceProviderInstance != before.ProviderInstance {
		t.Fatal("exact replay did not preserve captured prompt material")
	}
	if executor.child.ParentRunID != source.RunID || executor.child.SourceReviewID != source.ReviewID || executor.child.Publication.ParentRunID != source.RunID || executor.child.Publication.SourceReviewID != source.ReviewID || executor.child.Publication.SourceManifestURI != source.Prompt.URI || executor.child.Publication.SourceManifestSHA256 != source.Prompt.SHA256 {
		t.Fatalf("child lineage/publication authority = %#v", executor.child)
	}
	if reader.calls != 2 || executor.calls != 1 {
		t.Fatalf("calls = reader %d executor %d", reader.calls, executor.calls)
	}
}
func TestStartRerunExactSelectsStoredPrimaryProviderRoute(t *testing.T) {
	source := validRerunSource()
	reader := &rerunSourceReader{source: source}
	executor := &rerunExecutor{}
	primary, err := ports.NewProviderRoute(source.ProviderInstance, mustRerunConcurrencyKey(t))
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := review.NewScheduledAssignment(domain.RoleSecurity, true, primary, nil)
	if err != nil {
		t.Fatal(err)
	}
	service := testRerunServiceWithAssignments(t, reader, executor, []review.Assignment{assignment})

	if _, err := service.StartRerun(context.Background(), Request{SourceRunID: source.RunID, SourceAttemptID: source.AttemptID, ReplayMode: ExactReplay}); err != nil {
		t.Fatal(err)
	}
	if assignment := executor.child.Assignments[0]; assignment.ProviderInstance() != source.ProviderInstance || assignment.HasFallback() {
		t.Fatalf("exact primary assignment = %#v, want sole source provider route", assignment)
	}
}

func TestStartRerunExactSelectsStoredFallbackProviderRoute(t *testing.T) {
	source := validRerunSource()
	reader := &rerunSourceReader{source: source}
	executor := &rerunExecutor{}
	primary, err := ports.NewProviderRoute("current-primary", mustRerunConcurrencyKey(t))
	if err != nil {
		t.Fatal(err)
	}
	fallbackKey, err := ports.ParseConcurrencyKey("rerun-fallback")
	if err != nil {
		t.Fatal(err)
	}
	fallback, err := ports.NewProviderRoute(source.ProviderInstance, fallbackKey)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := review.NewScheduledAssignment(domain.RoleSecurity, true, primary, &fallback)
	if err != nil {
		t.Fatal(err)
	}
	service := testRerunServiceWithAssignments(t, reader, executor, []review.Assignment{assignment})

	if _, err := service.StartRerun(context.Background(), Request{SourceRunID: source.RunID, SourceAttemptID: source.AttemptID, ReplayMode: ExactReplay}); err != nil {
		t.Fatal(err)
	}
	if assignment := executor.child.Assignments[0]; assignment.ProviderInstance() != source.ProviderInstance || assignment.HasFallback() || assignment.PrimaryRoute() != fallback {
		t.Fatalf("exact fallback assignment = %#v, want promoted sole source provider route", assignment)
	}
}

func TestStartRerunExactRejectsChangedAssignmentProvider(t *testing.T) {
	source := validRerunSource()
	reader := &rerunSourceReader{source: source}
	executor := &rerunExecutor{}
	route, err := ports.NewProviderRoute("changed-provider", mustRerunConcurrencyKey(t))
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := review.NewScheduledAssignment(domain.RoleSecurity, true, route, nil)
	if err != nil {
		t.Fatal(err)
	}
	service := testRerunServiceWithAssignments(t, reader, executor, []review.Assignment{assignment})

	if _, err := service.StartRerun(context.Background(), Request{SourceRunID: source.RunID, SourceAttemptID: source.AttemptID, ReplayMode: ExactReplay}); err == nil {
		t.Fatal("exact replay accepted changed assignment provider")
	}
	if executor.calls != 0 {
		t.Fatalf("executor calls = %d, want no child execution", executor.calls)
	}
}

func TestStartRerunPropagatesCommittedTerminalExitAndFailsClosedWithoutIt(t *testing.T) {
	source := validRerunSource()
	request := Request{SourceRunID: source.RunID, SourceAttemptID: source.AttemptID, ReplayMode: ExactReplay}

	for _, test := range []struct {
		name string
		code domain.OperationalExitCode
	}{
		{name: "pass", code: domain.ExitCommittedPass},
		{name: "ci_rejected", code: domain.ExitCommittedCIRejected},
		{name: "incomplete_coverage", code: domain.ExitIncompleteCoverage},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &rerunSourceReader{source: source}
			service := testRerunService(t, reader, &rerunExecutor{exitCode: test.code})

			result, err := service.StartRerun(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			exit, ok := result.TerminalExit()
			if !ok || exit.Code() != test.code {
				t.Fatalf("terminal exit = (%#v, %t), want code %d", exit, ok, test.code)
			}
			if reader.calls != 2 {
				t.Fatalf("reader calls = %d, want re-observation after committed child", reader.calls)
			}
		})
	}

	malformedExit := domain.OperationalExitDecision{}
	for _, test := range []struct {
		name   string
		result ChildReplayResult
	}{
		{name: "absent", result: ChildReplayResult{
			SessionID: source.SessionID, RunID: mustRerunRun(rerunChildRun), ParentRunID: source.RunID, SourceRunID: source.RunID,
			SourceReviewID: source.ReviewID, SourceAttemptID: source.AttemptID, ExecutionInvocationID: "exec-child",
			PromptIdentity: "prompt-child", PromptManifestURI: "kar://prompt/child", PromptManifestSHA256: rerunDigest([]byte("child")),
			ReplayMode: ExactReplay, ExactReplay: true,
		}},
		{name: "malformed", result: ChildReplayResult{
			SessionID: source.SessionID, RunID: mustRerunRun(rerunChildRun), ParentRunID: source.RunID, SourceRunID: source.RunID,
			SourceReviewID: source.ReviewID, SourceAttemptID: source.AttemptID, ExecutionInvocationID: "exec-child",
			PromptIdentity: "prompt-child", PromptManifestURI: "kar://prompt/child", PromptManifestSHA256: rerunDigest([]byte("child")),
			ReplayMode: ExactReplay, ExactReplay: true, terminalExit: &malformedExit,
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &rerunSourceReader{source: source}
			service := testRerunService(t, reader, &rerunExecutor{result: &test.result})
			if _, err := service.StartRerun(context.Background(), request); !errors.Is(err, ErrInvalidChild) {
				t.Fatalf("invalid terminal exit error = %v, want invalid child", err)
			}
			if reader.calls != 1 {
				t.Fatalf("reader calls = %d, want no re-observation for malformed child result", reader.calls)
			}
		})
	}
}

func TestStartRerunRecomposeHasNoExactMaterial(t *testing.T) {
	source := validRerunSource()
	reader := &rerunSourceReader{source: source}
	executor := &rerunExecutor{}
	service := testRerunService(t, reader, executor)
	_, err := service.StartRerun(context.Background(), Request{SourceRunID: source.RunID, SourceAttemptID: source.AttemptID, ReplayMode: RecomposeReplay})
	if err != nil {
		t.Fatal(err)
	}
	if executor.child.Mode != RecomposeReplay || executor.child.Exact != nil || executor.child.Scope != source.Prompt.Scope || executor.child.Role != source.Prompt.Role {
		t.Fatalf("recompose child = %#v", executor.child)
	}
	if assignments := executor.child.Assignments; len(assignments) != 1 || assignments[0].Role() != domain.RoleSecurity {
		t.Fatalf("recompose assignments = %#v, want one security assignment", assignments)
	}
	if roles := executor.child.Run.RoleTasks(); len(roles) != 1 || roles[0].Role() != domain.RoleSecurity {
		t.Fatalf("recompose role tasks = %#v, want one security role", roles)
	}
}
func TestSourceAttemptDigestRejectsEveryBoundFieldMutation(t *testing.T) {
	request := Request{SourceRunID: mustRerunRun(rerunSourceRun), SourceAttemptID: mustRerunAttempt(), ReplayMode: ExactReplay}
	cases := []struct {
		name   string
		mutate func(*SourceAttempt)
	}{
		{"session", func(source *SourceAttempt) {
			source.SessionID, _ = domain.ParseSessionID("s_019f596a-cf81-7c67-b265-f37053d51ccf")
		}},
		{"run", func(source *SourceAttempt) { source.RunID = mustRerunRun(rerunChildRun) }},
		{"review", func(source *SourceAttempt) {
			source.ReviewID, _ = domain.ParseReviewID("019f596a-cf81-7c67-b265-f37053d51ccf")
		}},
		{"attempt", func(source *SourceAttempt) {
			source.AttemptID, _ = domain.ParseAttemptID("a_019f596a-cf81-7c67-b265-f37053d51ccf")
		}},
		{"provider", func(source *SourceAttempt) { source.ProviderInstance = "other-provider" }},
		{"target bytes", func(source *SourceAttempt) { source.Target.Bytes[0] = 'X' }},
		{"target hash", func(source *SourceAttempt) { source.Target.SHA256 = rerunDigest([]byte("other")) }},
		{"manifest uri", func(source *SourceAttempt) { source.Prompt.URI = "kar://prompt/other" }},
		{"manifest hash", func(source *SourceAttempt) { source.Prompt.SHA256 = rerunDigest([]byte("other manifest")) }},
		{"stdin", func(source *SourceAttempt) { source.Prompt.ComposedStdin[0] = 'X' }},
		{"stdin hash", func(source *SourceAttempt) { source.Prompt.ComposedStdinSHA256 = rerunDigest([]byte("other stdin")) }},
		{"source invocation", func(source *SourceAttempt) { source.Prompt.SourceInvocationID = "other-source" }},
		{"execution invocation", func(source *SourceAttempt) { source.Prompt.ExecutionInvocationID = "other-execution" }},
		{"adapter profile", func(source *SourceAttempt) { source.Prompt.AdapterProfile = "other-profile" }},
		{"parameter name", func(source *SourceAttempt) { source.Prompt.Parameters[0].Name = "top_p" }},
		{"parameter value", func(source *SourceAttempt) { source.Prompt.Parameters[0].Value = "1" }},
		{"scope", func(source *SourceAttempt) { source.Prompt.Scope = "other-scope" }},
		{"role", func(source *SourceAttempt) { source.Prompt.Role = "logic" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			source := cloneRerunSource(validRerunSource())
			test.mutate(&source)
			if err := validateSource(source, request); !errors.Is(err, ErrSourceCorrupt) {
				t.Fatalf("validateSource() error = %v, want corrupt source", err)
			}
		})
	}
}
func TestStartRerunKeepsCommittedChildAfterLateCancellation(t *testing.T) {
	source := validRerunSource()
	ctx, cancel := context.WithCancel(context.Background())
	reader := &rerunSourceReader{source: source, requireActive: true}
	executor := &rerunExecutor{cancel: cancel}
	service := testRerunService(t, reader, executor)

	result, err := service.StartRerun(ctx, Request{SourceRunID: source.RunID, SourceAttemptID: source.AttemptID, ReplayMode: ExactReplay})
	if err != nil {
		t.Fatalf("StartRerun() error = %v", err)
	}
	if result.RunID != mustRerunRun(rerunChildRun) || reader.calls != 2 || executor.calls != 1 {
		t.Fatalf("result = %#v, calls = reader %d executor %d, want committed child and detached reread", result, reader.calls, executor.calls)
	}
}

func TestStartRerunRejectsMalformedIDsAndStaleSource(t *testing.T) {
	source := validRerunSource()
	reader := &rerunSourceReader{source: source}
	executor := &rerunExecutor{}
	service := testRerunService(t, reader, executor)
	if _, err := service.StartRerun(context.Background(), Request{SourceAttemptID: source.AttemptID, ReplayMode: ExactReplay}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("malformed run ID error = %v", err)
	}
	if _, err := service.StartRerun(context.Background(), Request{SourceRunID: source.RunID, ReplayMode: ExactReplay}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("malformed attempt ID error = %v", err)
	}
	reader.err = errors.New("source attempt is stale")
	if _, err := service.StartRerun(context.Background(), Request{SourceRunID: source.RunID, SourceAttemptID: source.AttemptID, ReplayMode: ExactReplay}); err == nil {
		t.Fatal("stale source was accepted")
	}
}

func TestStartRerunClassifiesSourceMutationAsSecurityPolicy(t *testing.T) {
	source := validRerunSource()
	mutated := cloneRerunSource(source)
	mutated.ProviderInstance = "different-provider"
	mutated.ImmutableSHA256 = sourceAttemptDigest(mutated)
	reader := &rerunSourceReader{source: source, observed: &mutated}
	service := testRerunService(t, reader, &rerunExecutor{})

	_, err := service.StartRerun(context.Background(), Request{SourceRunID: source.RunID, SourceAttemptID: source.AttemptID, ReplayMode: ExactReplay})
	if !errors.Is(err, ErrSourceMutated) {
		t.Fatalf("source mutation error = %v, want ErrSourceMutated", err)
	}
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureSecurityPolicy {
		t.Fatalf("source mutation error = %v, want security policy failure", err)
	}
}

func TestStartRerunRejectsMissingOrStaleAuthority(t *testing.T) {
	source := validRerunSource()
	reader := &rerunSourceReader{source: source}
	executor := &rerunExecutor{}

	if service, err := NewService(reader, executor, Config{}); err == nil || service != nil {
		t.Fatalf("NewService() = (%#v, %v), want missing authority rejection", service, err)
	}

	missingIdentity := cloneRerunSource(source)
	missingIdentity.Target.Identity = domain.TargetIdentity{}
	missingIdentity.ImmutableSHA256 = sourceAttemptDigest(missingIdentity)
	service := testRerunService(t, &rerunSourceReader{source: missingIdentity}, executor)
	if _, err := service.StartRerun(context.Background(), Request{SourceRunID: source.RunID, SourceAttemptID: source.AttemptID, ReplayMode: ExactReplay}); !errors.Is(err, ErrSourceCorrupt) {
		t.Fatalf("missing source target identity error = %v, want corrupt source", err)
	}
	if executor.calls != 0 {
		t.Fatalf("executor calls = %d, want no child execution", executor.calls)
	}

	stale := &rerunExecutor{resultID: source.RunID}
	service = testRerunService(t, reader, stale)
	if _, err := service.StartRerun(context.Background(), Request{SourceRunID: source.RunID, SourceAttemptID: source.AttemptID, ReplayMode: ExactReplay}); !errors.Is(err, ErrInvalidChild) {
		t.Fatalf("stale child authority error = %v, want invalid child", err)
	}
}

func validRerunSource() SourceAttempt {
	target := []byte("immutable target")
	stdin := []byte("captured prompt")
	identity, err := domain.NewTargetIdentity(domain.TargetIdentityInput{Kind: domain.TargetPatch, SHA256: rerunDigest(target)})
	if err != nil {
		panic(err)
	}
	source := SourceAttempt{SessionID: mustRerunSession(), RunID: mustRerunRun(rerunSourceRun), ReviewID: mustRerunReview(), AttemptID: mustRerunAttempt(), ProviderInstance: "kimi-main", Target: Target{Identity: identity, Bytes: target, SHA256: rerunDigest(target)}, Prompt: PromptManifest{URI: "kar://prompt/source", SHA256: rerunDigest([]byte("manifest")), ComposedStdin: stdin, ComposedStdinSHA256: rerunDigest(stdin), CompleteStdinSHA256: appprompt.CompleteStdinSHA256(stdin), SourceInvocationID: "source-invocation", ExecutionInvocationID: "source-execution", TemplateID: "root-review", TemplateVersion: "v1", TemplateSHA256: rerunDigest([]byte("template")), AdapterProfile: "kimi-main", Parameters: []Parameter{{Name: "temperature", Value: "0"}}, Scope: "repository", Role: "security"}}
	source.ImmutableSHA256 = sourceAttemptDigest(source)
	return source
}
func cloneRerunSource(source SourceAttempt) SourceAttempt {
	source.Target.Bytes = append([]byte(nil), source.Target.Bytes...)
	source.Prompt.ComposedStdin = append([]byte(nil), source.Prompt.ComposedStdin...)
	source.Prompt.Parameters = append([]Parameter(nil), source.Prompt.Parameters...)
	return source
}
func rerunDigest(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
func mustRerunSession() domain.SessionID {
	id, err := domain.ParseSessionID(rerunSession)
	if err != nil {
		panic(err)
	}
	return id
}
func mustRerunRun(value string) domain.RunID {
	id, err := domain.ParseRunID(value)
	if err != nil {
		panic(err)
	}
	return id
}
func mustRerunAttempt() domain.AttemptID {
	id, err := domain.ParseAttemptID(rerunAttempt)
	if err != nil {
		panic(err)
	}
	return id
}
func mustRerunReview() domain.ReviewID {
	id, err := domain.ParseReviewID(rerunReview)
	if err != nil {
		panic(err)
	}
	return id
}

type rerunClock struct{ now time.Time }

func (clock rerunClock) Now() time.Time { return clock.now }

type rerunIDs struct {
	id  domain.RunID
	err error
}

func (ids rerunIDs) NewRunID(time.Time) (domain.RunID, error) { return ids.id, ids.err }

func testRerunService(t *testing.T, reader SourceReader, executor ChildReplayExecutor) *Service {
	t.Helper()
	route, err := ports.NewProviderRoute("kimi-main", mustRerunConcurrencyKey(t))
	if err != nil {
		t.Fatal(err)
	}
	logic, err := review.NewScheduledAssignment(domain.RoleLogic, true, route, nil)
	if err != nil {
		t.Fatal(err)
	}
	security, err := review.NewScheduledAssignment(domain.RoleSecurity, true, route, nil)
	if err != nil {
		t.Fatal(err)
	}
	return testRerunServiceWithAssignments(t, reader, executor, []review.Assignment{logic, security})
}

func testRerunServiceWithAssignments(t *testing.T, reader SourceReader, executor ChildReplayExecutor, assignments []review.Assignment) *Service {
	t.Helper()
	service, err := NewService(reader, executor, Config{
		Clock:       rerunClock{now: time.Date(2026, time.July, 18, 0, 0, 0, 0, time.UTC)},
		IDs:         rerunIDs{id: mustRerunRun(rerunChildRun)},
		Assignments: assignments,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}
func mustRerunConcurrencyKey(t *testing.T) ports.ConcurrencyKey {
	t.Helper()
	key, err := ports.ParseConcurrencyKey("rerun-child")
	if err != nil {
		t.Fatal(err)
	}
	return key
}

var _ ports.Clock = rerunClock{}

func mustChildReplayResult(child ChildReplay, resultID domain.RunID, code domain.OperationalExitCode) ChildReplayResult {
	if resultID.String() == "" {
		resultID = child.Run.ID()
	}
	result, err := NewChildReplayResult(
		child.SessionID, resultID, child.ParentRunID, child.SourceRunID, child.SourceReviewID, child.SourceAttemptID,
		"exec-child", "prompt-child", "kar://prompt/child", rerunDigest([]byte("child")), child.Mode, child.Mode == ExactReplay,
		mustRerunCommittedExit(code),
	)
	if err != nil {
		panic(err)
	}
	return result
}

func mustRerunCommittedExit(code domain.OperationalExitCode) domain.OperationalExitDecision {
	reason, err := domain.NewExitReason(code, "committed")
	if err != nil {
		panic(err)
	}
	input, err := domain.NewOperationalExitInput([]domain.ExitReason{reason})
	if err != nil {
		panic(err)
	}
	exit, err := domain.ReduceOperationalExit(input)
	if err != nil {
		panic(err)
	}
	return exit
}
