package delta

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type deltaClock struct{ now time.Time }

func (clock deltaClock) Now() time.Time { return clock.now }

type deltaIDs struct{ id domain.RunID }

func (ids deltaIDs) NewRunID(time.Time) (domain.RunID, error) { return ids.id, nil }

type deltaSources struct {
	snapshots     []SourceSnapshot
	err           error
	calls         int
	requireActive bool
}

func (sources *deltaSources) ReadSource(ctx context.Context, _ domain.RunID) (SourceSnapshot, error) {
	sources.calls++
	if sources.requireActive && ctx.Err() != nil {
		return SourceSnapshot{}, ctx.Err()
	}
	if sources.err != nil {
		return SourceSnapshot{}, sources.err
	}
	index := sources.calls - 1
	if index >= len(sources.snapshots) {
		index = len(sources.snapshots) - 1
	}
	return sources.snapshots[index], nil
}

type deltaCapturer struct {
	target ImmutableTarget
	err    error
}

func (capturer deltaCapturer) CaptureTarget(context.Context, TargetRequest) (ImmutableTarget, error) {
	return capturer.target, capturer.err
}

type deltaComparator struct {
	delta   Delta
	err     error
	source  ImmutableTarget
	current ImmutableTarget
	cancel  context.CancelFunc
}

func (comparator *deltaComparator) Compare(_ context.Context, source, current ImmutableTarget) (Delta, error) {
	comparator.source, comparator.current = source, current
	if comparator.cancel != nil {
		comparator.cancel()
	}
	return comparator.delta, comparator.err
}

type deltaExecutor struct {
	request  ChildRequest
	err      error
	mutate   bool
	calls    int
	cancel   context.CancelFunc
	result   *ExecutionResult
	exitCode domain.OperationalExitCode
}

func (executor *deltaExecutor) ExecuteDelta(_ context.Context, request ChildRequest) (ExecutionResult, error) {
	executor.calls++
	executor.request = request
	if executor.mutate {
		if len(request.Delta.Bytes) > 0 {
			request.Delta.Bytes[0] = 'X'
		}
		if len(request.SourceTarget.bytes) > 0 {
			request.SourceTarget.bytes[0] = 'X'
		}
		if len(request.CurrentTarget.bytes) > 0 {
			request.CurrentTarget.bytes[0] = 'X'
		}
	}
	if executor.cancel != nil {
		executor.cancel()
	}
	if executor.err != nil {
		return ExecutionResult{}, executor.err
	}
	if executor.result != nil {
		return *executor.result, nil
	}
	return mustDeltaExecutionResult(request, executor.exitCode), nil
}

func TestStartDeltaRunCreatesLineageBoundChild(t *testing.T) {
	source := testSource(t, "source bytes", "source-receipt")
	current := testTarget(t, "current bytes")
	childID := testRunID(t, "r_019f596a-d175-7321-b920-c2d312c82cc2")
	sources := &deltaSources{snapshots: []SourceSnapshot{source, source}}
	comparator := &deltaComparator{delta: Delta{Bytes: []byte("A-to-B")}}
	executor := &deltaExecutor{}
	service := testService(t, sources, deltaCapturer{target: current}, comparator, deltaIDs{id: childID}, executor)

	result, err := service.StartDeltaRun(context.Background(), StartRequest{
		SourceRunID: source.RunID,
		Target:      TargetRequest{Kind: TargetDiff, Value: "HEAD"},
		Roles:       []domain.Role{domain.RoleSecurity, domain.RoleLogic},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RunID != childID || result.SessionID != source.SessionID || result.ReviewArtifactURI != "reviews/child.json" {
		t.Fatalf("unexpected result: %#v", result)
	}
	parent, hasParent := executor.request.Run.ParentRunID()
	sourceID, hasSource := executor.request.Run.SourceRunID()
	if !hasParent || !hasSource || parent != source.RunID || sourceID != source.RunID {
		t.Fatalf("child lineage = parent %q source %q", parent.String(), sourceID.String())
	}
	if executor.request.SourceReviewID != source.ReviewID || executor.request.SourceTarget.SHA256() != source.Target.SHA256() {
		t.Fatal("executor did not receive source identity")
	}
	roles := executor.request.Run.RoleTasks()
	if len(roles) != 2 || roles[0].Role() != domain.RoleLogic || roles[1].Role() != domain.RoleSecurity {
		t.Fatalf("child roles are not deterministic: %#v", roles)
	}
	if sources.calls != 2 {
		t.Fatalf("source reads = %d, want 2", sources.calls)
	}
}

func TestStartDeltaRunPropagatesCommittedTerminalExitAndFailsClosedWithoutIt(t *testing.T) {
	source := testSource(t, "source bytes", "source-receipt")
	current := testTarget(t, "current bytes")
	request := StartRequest{SourceRunID: source.RunID, Target: TargetRequest{Kind: TargetDiff, Value: "HEAD"}, Roles: []domain.Role{domain.RoleLogic, domain.RoleSecurity}}

	for _, test := range []struct {
		name string
		code domain.OperationalExitCode
	}{
		{name: "pass", code: domain.ExitCommittedPass},
		{name: "ci_rejected", code: domain.ExitCommittedCIRejected},
		{name: "incomplete_coverage", code: domain.ExitIncompleteCoverage},
	} {
		t.Run(test.name, func(t *testing.T) {
			sources := &deltaSources{snapshots: []SourceSnapshot{source, source}}
			executor := &deltaExecutor{exitCode: test.code}
			service := testService(t, sources, deltaCapturer{target: current}, &deltaComparator{}, deltaIDs{id: testRunID(t, "r_019f596a-d175-7321-b920-c2d312c82cc2")}, executor)

			result, err := service.StartDeltaRun(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			exit, ok := result.TerminalExit()
			if !ok || exit.Code() != test.code {
				t.Fatalf("terminal exit = (%#v, %t), want code %d", exit, ok, test.code)
			}
			if sources.calls != 2 {
				t.Fatalf("source reads = %d, want re-observation after committed child", sources.calls)
			}
		})
	}

	malformedExit := domain.OperationalExitDecision{}
	for _, test := range []struct {
		name   string
		result ExecutionResult
	}{
		{name: "absent", result: ExecutionResult{SessionID: source.SessionID, RunID: testRunID(t, "r_019f596a-d175-7321-b920-c2d312c82cc2"), ReviewArtifactURI: "reviews/child.json"}},
		{name: "malformed", result: ExecutionResult{SessionID: source.SessionID, RunID: testRunID(t, "r_019f596a-d175-7321-b920-c2d312c82cc2"), ReviewArtifactURI: "reviews/child.json", terminalExit: &malformedExit}},
	} {
		t.Run(test.name, func(t *testing.T) {
			sources := &deltaSources{snapshots: []SourceSnapshot{source, source}}
			service := testService(t, sources, deltaCapturer{target: current}, &deltaComparator{}, deltaIDs{id: testRunID(t, "r_019f596a-d175-7321-b920-c2d312c82cc2")}, &deltaExecutor{result: &test.result})
			if _, err := service.StartDeltaRun(context.Background(), request); err == nil {
				t.Fatal("StartDeltaRun accepted a child without valid terminal exit authority")
			}
			if sources.calls != 1 {
				t.Fatalf("source reads = %d, want no re-observation for malformed child result", sources.calls)
			}
		})
	}
}

func TestStartDeltaRunRejectsInvalidRoles(t *testing.T) {
	source := testSource(t, "source bytes", "source-receipt")
	sources := &deltaSources{snapshots: []SourceSnapshot{source}}
	service := testService(t, sources, deltaCapturer{}, &deltaComparator{}, deltaIDs{id: testRunID(t, "r_019f596a-d175-7321-b920-c2d312c82cc2")}, &deltaExecutor{})

	_, err := service.StartDeltaRun(context.Background(), StartRequest{
		SourceRunID: source.RunID,
		Target:      TargetRequest{Kind: TargetDiff, Value: "HEAD"},
		Roles:       []domain.Role{domain.RoleLogic, domain.RoleLogic, domain.RoleSecurity},
	})
	if err == nil {
		t.Fatal("StartDeltaRun accepted duplicate roles")
	}
	if sources.calls != 1 {
		t.Fatalf("source reads = %d, want 1", sources.calls)
	}
}
func TestStartDeltaRunRejectsIncompleteP2Authority(t *testing.T) {
	source := testSource(t, "source bytes", "source-receipt")
	current := testTarget(t, "current bytes")
	request := StartRequest{SourceRunID: source.RunID, Target: TargetRequest{Kind: TargetDiff, Value: "HEAD"}, Roles: []domain.Role{domain.RoleLogic, domain.RoleSecurity}}

	cases := map[string]func(*SourceSnapshot){
		"final":    func(snapshot *SourceSnapshot) { snapshot.FinalSHA256 = "" },
		"manifest": func(snapshot *SourceSnapshot) { snapshot.ManifestSHA256 = "" },
		"receipt":  func(snapshot *SourceSnapshot) { snapshot.Receipt = "" },
		"target":   func(snapshot *SourceSnapshot) { snapshot.Target = testTarget(t, "source bytes") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			incomplete := source
			mutate(&incomplete)
			executor := &deltaExecutor{}
			service := testService(t, &deltaSources{snapshots: []SourceSnapshot{incomplete}}, deltaCapturer{target: current}, &deltaComparator{}, deltaIDs{id: testRunID(t, "r_019f596a-d175-7321-b920-c2d312c82cc2")}, executor)
			if _, err := service.StartDeltaRun(context.Background(), request); err == nil {
				t.Fatal("StartDeltaRun accepted incomplete P2 source authority")
			}
			if executor.calls != 0 {
				t.Fatalf("executor calls = %d, want no child execution", executor.calls)
			}
		})
	}
}

func TestStartDeltaRunFailsClosedForMissingOrStaleSource(t *testing.T) {
	source := testSource(t, "source bytes", "source-receipt")
	current := testTarget(t, "current bytes")
	request := StartRequest{SourceRunID: source.RunID, Target: TargetRequest{Kind: TargetDiff, Value: "HEAD"}, Roles: []domain.Role{domain.RoleLogic, domain.RoleSecurity}}
	for name, sources := range map[string]*deltaSources{
		"missing": {err: errors.New("source not found")},
		"stale":   {snapshots: []SourceSnapshot{func() SourceSnapshot { stale := source; stale.Target = current; return stale }()}},
		"mutated": {snapshots: []SourceSnapshot{source, func() SourceSnapshot { changed := source; changed.Receipt = "different-receipt"; return changed }()}},
	} {
		t.Run(name, func(t *testing.T) {
			service := testService(t, sources, deltaCapturer{target: current}, &deltaComparator{delta: Delta{}}, deltaIDs{id: testRunID(t, "r_019f596a-d175-7321-b920-c2d312c82cc2")}, &deltaExecutor{})
			if _, err := service.StartDeltaRun(context.Background(), request); err == nil {
				t.Fatal("StartDeltaRun accepted an unavailable, stale, or changed source")
			}
		})
	}
}
func TestStartDeltaRunKeepsCommittedChildAfterLateCancellation(t *testing.T) {
	source := testSource(t, "source bytes", "source-receipt")
	current := testTarget(t, "current bytes")
	ctx, cancel := context.WithCancel(context.Background())
	executor := &deltaExecutor{cancel: cancel}
	sources := &deltaSources{snapshots: []SourceSnapshot{source, source}, requireActive: true}
	service := testService(t, sources, deltaCapturer{target: current}, &deltaComparator{}, deltaIDs{id: testRunID(t, "r_019f596a-d175-7321-b920-c2d312c82cc2")}, executor)

	result, err := service.StartDeltaRun(ctx, StartRequest{
		SourceRunID: source.RunID,
		Target:      TargetRequest{Kind: TargetDiff, Value: "HEAD"},
		Roles:       []domain.Role{domain.RoleLogic, domain.RoleSecurity},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RunID != executor.request.Run.ID() || sources.calls != 2 || executor.calls != 1 {
		t.Fatalf("result = %#v, source reads = %d, executor calls = %d; want committed child, detached reread, and one execution", result, sources.calls, executor.calls)
	}
}
func TestStartDeltaRunRejectsNilAndCancelledBeforeLaterDependencies(t *testing.T) {
	source := testSource(t, "source bytes", "source-receipt")
	request := StartRequest{SourceRunID: source.RunID, Target: TargetRequest{Kind: TargetDiff, Value: "HEAD"}, Roles: []domain.Role{domain.RoleLogic, domain.RoleSecurity}}
	var nilService *Service
	if _, err := nilService.StartDeltaRun(context.Background(), request); err == nil {
		t.Fatal("nil service was accepted")
	}

	sources := &deltaSources{snapshots: []SourceSnapshot{source, source}}
	executor := &deltaExecutor{}
	service := testService(t, sources, deltaCapturer{target: testTarget(t, "current bytes")}, &deltaComparator{}, deltaIDs{id: testRunID(t, "r_019f596a-d175-7321-b920-c2d312c82cc2")}, executor)
	if _, err := service.StartDeltaRun(nil, request); err == nil {
		t.Fatal("nil context was accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.StartDeltaRun(cancelled, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error = %v", err)
	}
	if sources.calls != 0 || executor.calls != 0 {
		t.Fatalf("cancelled entry invoked dependencies: source=%d executor=%d", sources.calls, executor.calls)
	}

	ctx, cancel := context.WithCancel(context.Background())
	comparator := &deltaComparator{cancel: cancel}
	executor = &deltaExecutor{}
	service = testService(t, &deltaSources{snapshots: []SourceSnapshot{source, source}}, deltaCapturer{target: testTarget(t, "current bytes")}, comparator, deltaIDs{id: testRunID(t, "r_019f596a-d175-7321-b920-c2d312c82cc2")}, executor)
	if _, err := service.StartDeltaRun(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation after compare error = %v", err)
	}
	if executor.calls != 0 {
		t.Fatal("executor ran after comparison cancelled the context")
	}
}
func TestStartDeltaRunRejectsSourceMutationAfterOneChildExecution(t *testing.T) {
	source := testSource(t, "source bytes", "source-receipt")
	current := testTarget(t, "current bytes")
	mutated := source
	mutated.Receipt = "different-receipt"
	sources := &deltaSources{snapshots: []SourceSnapshot{source, mutated}}
	executor := &deltaExecutor{}
	service := testService(t, sources, deltaCapturer{target: current}, &deltaComparator{}, deltaIDs{id: testRunID(t, "r_019f596a-d175-7321-b920-c2d312c82cc2")}, executor)

	_, err := service.StartDeltaRun(context.Background(), StartRequest{
		SourceRunID: source.RunID,
		Target:      TargetRequest{Kind: TargetDiff, Value: "HEAD"},
		Roles:       []domain.Role{domain.RoleLogic, domain.RoleSecurity},
	})
	if err == nil {
		t.Fatal("StartDeltaRun accepted a source mutation after child execution")
	}
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureSecurityPolicy {
		t.Fatalf("source mutation error = %v, want security policy failure", err)
	}
	if sources.calls != 2 || executor.calls != 1 {
		t.Fatalf("source reads = %d, executor calls = %d; want source recheck after one child execution", sources.calls, executor.calls)
	}
}

func TestStartDeltaRunDefensivelyCopiesComparatorOutput(t *testing.T) {
	source := testSource(t, "source bytes", "source-receipt")
	current := testTarget(t, "current bytes")
	comparator := &deltaComparator{delta: Delta{Bytes: []byte("delta")}}
	executor := &deltaExecutor{mutate: true}
	service := testService(t, &deltaSources{snapshots: []SourceSnapshot{source, source}}, deltaCapturer{target: current}, comparator, deltaIDs{id: testRunID(t, "r_019f596a-d175-7321-b920-c2d312c82cc2")}, executor)

	if _, err := service.StartDeltaRun(context.Background(), StartRequest{SourceRunID: source.RunID, Target: TargetRequest{Kind: TargetDiff, Value: "HEAD"}, Roles: []domain.Role{domain.RoleLogic, domain.RoleSecurity}}); err != nil {
		t.Fatal(err)
	}
	if string(comparator.delta.Bytes) != "delta" {
		t.Fatalf("executor mutated comparator-owned bytes: %q", comparator.delta.Bytes)
	}
	if string(source.Target.Bytes()) != "source bytes" {
		t.Fatal("child execution mutated immutable source bytes")
	}
	if string(current.Bytes()) != "current bytes" {
		t.Fatal("child execution mutated immutable current bytes")
	}
}
func TestStartDeltaRunPreservesAllTargetKinds(t *testing.T) {
	source := testSource(t, "source bytes", "source-receipt")
	cases := []struct {
		name       string
		request    TargetRequest
		current    ImmutableTarget
		domainKind domain.TargetKind
	}{
		{name: "diff", request: TargetRequest{Kind: TargetDiff, Value: "HEAD"}, current: testTarget(t, "diff bytes"), domainKind: domain.TargetGit},
		{name: "patch", request: TargetRequest{Kind: TargetPatch, Value: "change.patch"}, current: testByteTarget(t, TargetPatch, "change.patch", "patch bytes"), domainKind: domain.TargetPatch},
		{name: "stdin", request: TargetRequest{Kind: TargetStdin, Value: "stdin"}, current: testByteTarget(t, TargetStdin, "stdin", "stdin bytes"), domainKind: domain.TargetStdin},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			executor := &deltaExecutor{}
			service := testService(t, &deltaSources{snapshots: []SourceSnapshot{source, source}}, deltaCapturer{target: test.current}, &deltaComparator{}, deltaIDs{id: testRunID(t, "r_019f596a-d175-7321-b920-c2d312c82cc2")}, executor)
			if _, err := service.StartDeltaRun(context.Background(), StartRequest{SourceRunID: source.RunID, Target: test.request, Roles: []domain.Role{domain.RoleLogic, domain.RoleSecurity}}); err != nil {
				t.Fatal(err)
			}
			if executor.request.CurrentTarget.Kind() != test.request.Kind || executor.request.CurrentTarget.Value() != test.request.Value || executor.request.CurrentTarget.Identity().Kind() != test.domainKind {
				t.Fatalf("current target was coerced: kind=%q value=%q identity=%q", executor.request.CurrentTarget.Kind(), executor.request.CurrentTarget.Value(), executor.request.CurrentTarget.Identity().Kind())
			}
			if executor.request.SourceTarget.Identity() != source.Target.Identity() || executor.request.CurrentTarget.Identity() == executor.request.SourceTarget.Identity() {
				t.Fatal("source and current identities were conflated")
			}
		})
	}
}
func TestStartDeltaRunRejectsCapturedKindOrValueCoercion(t *testing.T) {
	source := testSource(t, "source bytes", "source-receipt")
	for _, current := range []ImmutableTarget{
		testByteTarget(t, TargetStdin, "stdin", "stdin bytes"),
		testByteTarget(t, TargetPatch, "different.patch", "patch bytes"),
	} {
		service := testService(t, &deltaSources{snapshots: []SourceSnapshot{source}}, deltaCapturer{target: current}, &deltaComparator{}, deltaIDs{id: testRunID(t, "r_019f596a-d175-7321-b920-c2d312c82cc2")}, &deltaExecutor{})
		if _, err := service.StartDeltaRun(context.Background(), StartRequest{SourceRunID: source.RunID, Target: TargetRequest{Kind: TargetPatch, Value: "change.patch"}, Roles: []domain.Role{domain.RoleLogic, domain.RoleSecurity}}); err == nil {
			t.Fatal("capturer changed the requested target without rejection")
		}
	}
}

func TestImmutableTargetCopiesAndFailsClosed(t *testing.T) {
	input := []byte("patch bytes")
	target, err := NewByteImmutableTarget(TargetPatch, "change.patch", input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 'X'
	if string(target.Bytes()) != "patch bytes" {
		t.Fatal("target retained caller-owned bytes")
	}
	exposed := target.Bytes()
	exposed[0] = 'X'
	if string(target.Bytes()) != "patch bytes" {
		t.Fatal("target exposed mutable bytes")
	}
	large, err := NewByteImmutableTarget(TargetPatch, "change.patch", bytes.Repeat([]byte{'x'}, 180001))
	if err != nil || len(large.Bytes()) != 180001 {
		t.Fatalf("large target bytes rejected: %v", err)
	}
	if _, err := NewByteImmutableTarget(TargetDiff, "HEAD", []byte("not Git")); err == nil {
		t.Fatal("non-Git diff bytes accepted")
	}

	source := testSource(t, "source bytes", "source-receipt")
	for _, target := range []ImmutableTarget{
		testTarget(t, "different diff bytes"),
		testByteTarget(t, TargetPatch, "change.patch", "different patch bytes"),
		testByteTarget(t, TargetStdin, "stdin", "different stdin bytes"),
	} {
		t.Run(string(target.Kind()), func(t *testing.T) {
			malformed := target
			malformed.sha256 = "not-a-canonical-hash"
			service := testService(t, &deltaSources{snapshots: []SourceSnapshot{source}}, deltaCapturer{target: malformed}, &deltaComparator{}, deltaIDs{id: testRunID(t, "r_019f596a-d175-7321-b920-c2d312c82cc2")}, &deltaExecutor{})
			if _, err := service.StartDeltaRun(context.Background(), StartRequest{SourceRunID: source.RunID, Target: TargetRequest{Kind: target.Kind(), Value: target.Value()}, Roles: []domain.Role{domain.RoleLogic, domain.RoleSecurity}}); err == nil {
				t.Fatal("malformed target hash accepted")
			}
		})
	}
}

func testByteTarget(t *testing.T, kind TargetKind, value, content string) ImmutableTarget {
	t.Helper()
	target, err := NewByteImmutableTarget(kind, value, []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func testService(t *testing.T, sources SourceReader, capturer TargetCapturer, comparator Comparator, ids IdentityGenerator, executor ChildExecutor) *Service {
	t.Helper()
	service, err := NewService(deltaClock{now: time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)}, ids, sources, capturer, comparator, executor)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func testSource(t *testing.T, bytes, receipt string) SourceSnapshot {
	t.Helper()
	capturedTarget := testTarget(t, bytes)
	target, err := NewP2ImmutableTarget(capturedTarget.Identity(), capturedTarget.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	logic, err := domain.NewRoleTask(domain.RoleLogic, true, "logic-provider")
	if err != nil {
		t.Fatal(err)
	}
	security, err := domain.NewRoleTask(domain.RoleSecurity, true, "security-provider")
	if err != nil {
		t.Fatal(err)
	}
	sessionID := testSessionID(t, "s_019f596a-d173-7321-b920-c2d312c82cc2")
	runID := testRunID(t, "r_019f596a-d174-7321-b920-c2d312c82cc2")
	reviewID, err := domain.ParseReviewID("019f596a-d176-7321-b920-c2d312c82cc2")
	if err != nil {
		t.Fatal(err)
	}
	return SourceSnapshot{
		SessionID: sessionID, RunID: runID, ReviewID: reviewID, Roles: []domain.RoleTask{logic, security}, Target: target,
		FinalSHA256: targetDigest([]byte("final")), ManifestSHA256: targetDigest([]byte("manifest")), Receipt: receipt,
	}
}

func testTarget(t *testing.T, bytes string) ImmutableTarget {
	t.Helper()
	object, err := ports.ParseGitObjectID("0123456789abcdef0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	captured, err := ports.NewCapturedGitTarget("repository:test", object, object, object, nil, []byte(bytes))
	if err != nil {
		t.Fatal(err)
	}
	target, err := NewGitImmutableTarget("HEAD", captured)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func testSessionID(t *testing.T, value string) domain.SessionID {
	t.Helper()
	id, err := domain.ParseSessionID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testRunID(t *testing.T, value string) domain.RunID {
	t.Helper()
	id, err := domain.ParseRunID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustDeltaExecutionResult(request ChildRequest, code domain.OperationalExitCode) ExecutionResult {
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
	result, err := NewExecutionResult(request.Run.SessionID(), request.Run.ID(), "reviews/child.json", nil, exit)
	if err != nil {
		panic(err)
	}
	return result
}
