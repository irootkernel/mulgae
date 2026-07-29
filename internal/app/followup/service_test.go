package followup

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestStartFollowupRunPreservesSourceBytesAndUsesDefensiveCopies(t *testing.T) {
	source := testVerifiedSource(t)
	originalFinal := append([]byte(nil), source.Final...)
	originalManifest := append([]byte(nil), source.Manifest...)
	originalFinding := append([]byte(nil), source.Finding.Normalized...)
	originalExcerpt := append([]byte(nil), source.Finding.Excerpt...)
	reader := &followupTestSourceReader{source: source}
	capturer := &followupTestCapturer{target: testCurrentTarget(t, []byte("current target"))}
	executor := &followupTestExecutor{mutateInput: true, result: validExecutionResult(source)}
	service := mustFollowupService(t, reader, capturer, executor)

	result, err := service.StartFollowupRun(context.Background(), testRequest(source.RunID))
	if err != nil {
		t.Fatalf("StartFollowupRun() error = %v", err)
	}
	if result.SessionID() != source.SessionID || result.RunID() != executor.result.RunID || result.FollowupArtifactURI() != executor.result.FollowupArtifactURI {
		t.Fatalf("StartFollowupRun() result = %#v, want executor child identity", result)
	}
	if string(reader.source.Final) != string(originalFinal) || string(reader.source.Manifest) != string(originalManifest) || string(reader.source.Finding.Normalized) != string(originalFinding) || string(reader.source.Finding.Excerpt) != string(originalExcerpt) {
		t.Fatal("source bytes changed after child execution")
	}
	if string(capturer.target.Bytes) != "current target" {
		t.Fatal("current target bytes changed after child execution")
	}
	if string(executor.execution.Source.Final) == string(originalFinal) || string(executor.execution.Current.Bytes) == "current target" {
		t.Fatal("test executor did not mutate execution input")
	}
}

func TestStartFollowupRunPropagatesCommittedTerminalExitAndFailsClosedWithoutIt(t *testing.T) {
	source := testVerifiedSource(t)
	request := testRequest(source.RunID)

	for _, test := range []struct {
		name string
		code domain.OperationalExitCode
	}{
		{name: "pass", code: domain.ExitCommittedPass},
		{name: "ci_rejected", code: domain.ExitCommittedCIRejected},
		{name: "incomplete_coverage", code: domain.ExitIncompleteCoverage},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &followupTestSourceReader{source: source}
			executor := &followupTestExecutor{result: validExecutionResultWithExit(source, test.code)}
			service := mustFollowupService(t, reader, &followupTestCapturer{target: testCurrentTarget(t, []byte("current"))}, executor)

			result, err := service.StartFollowupRun(context.Background(), request)
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

	valid := validExecutionResult(source)
	malformedExit := domain.OperationalExitDecision{}
	for _, test := range []struct {
		name   string
		result ExecutionResult
	}{
		{name: "absent", result: ExecutionResult{SessionID: source.SessionID, RunID: valid.RunID, FollowupArtifactURI: valid.FollowupArtifactURI, ValidatedOutput: valid.ValidatedOutput}},
		{name: "malformed", result: ExecutionResult{SessionID: source.SessionID, RunID: valid.RunID, FollowupArtifactURI: valid.FollowupArtifactURI, ValidatedOutput: valid.ValidatedOutput, terminalExit: &malformedExit}},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &followupTestSourceReader{source: source}
			service := mustFollowupService(t, reader, &followupTestCapturer{target: testCurrentTarget(t, []byte("current"))}, &followupTestExecutor{result: test.result})
			if _, err := service.StartFollowupRun(context.Background(), request); err == nil {
				t.Fatal("StartFollowupRun accepted a child without valid terminal exit authority")
			}
			if reader.calls != 1 {
				t.Fatalf("reader calls = %d, want no re-observation for malformed child result", reader.calls)
			}
		})
	}
}

func TestStartFollowupRunFailsClosedForInvalidSource(t *testing.T) {
	base := testVerifiedSource(t)
	cases := []struct {
		name   string
		mutate func(*VerifiedSource)
	}{
		{
			name: "not P2 verified",
			mutate: func(source *VerifiedSource) {
				source.P2Verified = false
			},
		},
		{
			name: "missing final bytes",
			mutate: func(source *VerifiedSource) {
				source.Final = nil
			},
		},
		{
			name: "finding receipt mismatch",
			mutate: func(source *VerifiedSource) {
				source.Receipt.FindingSHA256 = digest([]byte("other finding"))
			},
		},
		{
			name: "wrong finding",
			mutate: func(source *VerifiedSource) {
				source.Finding.ID = "F999"
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			source := cloneSource(base)
			testCase.mutate(&source)
			reader := &followupTestSourceReader{source: source}
			executor := &followupTestExecutor{result: validExecutionResult(base)}
			service := mustFollowupService(t, reader, &followupTestCapturer{target: testCurrentTarget(t, []byte("current"))}, executor)

			_, err := service.StartFollowupRun(context.Background(), testRequest(base.RunID))
			var workflowError *Error
			if !errors.As(err, &workflowError) || workflowError.Kind != ErrorSource {
				t.Fatalf("StartFollowupRun() error = %v, want source failure", err)
			}
			if executor.called {
				t.Fatal("executor called for invalid source")
			}
		})
	}
}

func TestStartFollowupRunRejectsMalformedRequestAndCurrentTarget(t *testing.T) {
	source := testVerifiedSource(t)
	t.Run("malformed request target", func(t *testing.T) {
		executor := &followupTestExecutor{result: validExecutionResult(source)}
		service := mustFollowupService(t, &followupTestSourceReader{source: source}, &followupTestCapturer{target: testCurrentTarget(t, []byte("current"))}, executor)
		request := testRequest(source.RunID)
		request.Target.Value = "\n"
		_, err := service.StartFollowupRun(context.Background(), request)
		assertFollowupErrorKind(t, err, ErrorInvalidRequest)
		if executor.called {
			t.Fatal("executor called for malformed request")
		}
	})
	t.Run("current target identity mismatch", func(t *testing.T) {
		executor := &followupTestExecutor{result: validExecutionResult(source)}
		current := testCurrentTarget(t, []byte("current"))
		current.Bytes = []byte("tampered")
		service := mustFollowupService(t, &followupTestSourceReader{source: source}, &followupTestCapturer{target: current}, executor)
		_, err := service.StartFollowupRun(context.Background(), testRequest(source.RunID))
		assertFollowupErrorKind(t, err, ErrorExecution)
		if executor.called {
			t.Fatal("executor called for malformed current target")
		}
	})
}

func TestStartFollowupRunRejectsMutationDespiteExecutorSelfAttestation(t *testing.T) {
	source := testVerifiedSource(t)
	mutated := cloneSource(source)
	mutated.Final = []byte(`{"review":"mutated"}`)
	mutated.Receipt.FinalSHA256 = digest(mutated.Final)
	reader := &followupTestSourceReader{source: source, observed: &mutated}
	executor := &followupTestExecutor{result: validExecutionResult(source), selfAttestedSource: source.Receipt}
	service := mustFollowupService(t, reader, &followupTestCapturer{target: testCurrentTarget(t, []byte("current"))}, executor)

	_, err := service.StartFollowupRun(context.Background(), testRequest(source.RunID))
	assertFollowupErrorKind(t, err, ErrorMutation)
	assertFollowupFailureClass(t, err, domain.FailureSecurityPolicy)
	if reader.calls != 2 || !executor.called {
		t.Fatalf("calls = reader %d executor %t, want independent reread after child execution", reader.calls, executor.called)
	}
}

func assertFollowupFailureClass(t *testing.T, err error, want domain.FailureClass) {
	t.Helper()
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != want {
		t.Fatalf("error = %v, want failure class %s", err, want)
	}
}

func TestStartFollowupRunPreservesTypedExecutorFailure(t *testing.T) {
	source := testVerifiedSource(t)
	cause := &followupSecurityError{}
	executor := &followupTestExecutor{err: cause}
	service := mustFollowupService(t, &followupTestSourceReader{source: source}, &followupTestCapturer{target: testCurrentTarget(t, []byte("current"))}, executor)

	_, err := service.StartFollowupRun(context.Background(), testRequest(source.RunID))
	var got *followupSecurityError
	if !errors.As(err, &got) {
		t.Fatalf("StartFollowupRun() error = %v, want preserved security cause", err)
	}
	assertFollowupErrorKind(t, err, ErrorExecution)
}

func TestStartFollowupRunKeepsCommittedChildAfterLateCancellation(t *testing.T) {
	source := testVerifiedSource(t)
	ctx, cancel := context.WithCancel(context.Background())
	reader := &followupTestSourceReader{source: source, requireActive: true}
	executor := &followupTestExecutor{result: validExecutionResult(source), cancel: cancel}
	service := mustFollowupService(t, reader, &followupTestCapturer{target: testCurrentTarget(t, []byte("current"))}, executor)

	result, err := service.StartFollowupRun(ctx, testRequest(source.RunID))
	if err != nil {
		t.Fatalf("StartFollowupRun() error = %v", err)
	}
	if result.RunID() != executor.result.RunID || reader.calls != 2 {
		t.Fatalf("result = %#v, reader calls = %d, want committed child and detached reread", result, reader.calls)
	}
}
func TestStartFollowupRunAcceptsSchemaValidNonNumericFindingID(t *testing.T) {
	source := testVerifiedSource(t)
	source.Finding.ID = "F_SOURCE-1"
	request := testRequest(source.RunID)
	request.FindingID = source.Finding.ID
	executor := &followupTestExecutor{result: validExecutionResult(source)}
	service := mustFollowupService(t, &followupTestSourceReader{source: source}, &followupTestCapturer{target: testCurrentTarget(t, []byte("current"))}, executor)

	result, err := service.StartFollowupRun(context.Background(), request)
	if err != nil {
		t.Fatalf("StartFollowupRun() error = %v", err)
	}
	if result.RunID() != executor.result.RunID || !executor.called {
		t.Fatalf("result = %#v, executor called = %t", result, executor.called)
	}
}

func TestValidFindingIDMatchesFrozenSchemaGrammar(t *testing.T) {
	maximum := "A" + strings.Repeat("Z", 63)
	for _, value := range []string{"", "a", "A*", "A ", "A/", strings.Repeat("A", 65)} {
		if validFindingID(value) {
			t.Fatalf("validFindingID(%q) = true, want false", value)
		}
	}
	for _, value := range []string{"A", "F_SOURCE-1", maximum} {
		if !validFindingID(value) {
			t.Fatalf("validFindingID(%q) = false, want true", value)
		}
	}
}

type followupSecurityError struct{}
type followupSchemaValidatorFunc func(context.Context, ports.AssetID, []byte) error

func (fn followupSchemaValidatorFunc) Validate(ctx context.Context, id ports.AssetID, raw []byte) error {
	return fn(ctx, id, raw)
}

func (*followupSecurityError) Error() string { return "security policy violation" }

type followupTestSourceReader struct {
	source        VerifiedSource
	observed      *VerifiedSource
	err           error
	calls         int
	requireActive bool
}

func (reader *followupTestSourceReader) ReadFollowupSource(ctx context.Context, _ domain.RunID, _ string) (VerifiedSource, error) {
	reader.calls++
	if reader.requireActive && ctx.Err() != nil {
		return VerifiedSource{}, ctx.Err()
	}
	if reader.calls > 1 && reader.observed != nil {
		return *reader.observed, reader.err
	}
	return reader.source, reader.err
}

type followupTestCapturer struct{ target CurrentTarget }

func (capturer *followupTestCapturer) CaptureFollowupTarget(_ context.Context, _ Target) (CurrentTarget, error) {
	return capturer.target, nil
}

type followupTestExecutor struct {
	called             bool
	mutateInput        bool
	execution          Execution
	result             ExecutionResult
	err                error
	cancel             func()
	selfAttestedSource SourceReceipt
}

func (executor *followupTestExecutor) ExecuteFollowup(_ context.Context, execution Execution) (ExecutionResult, error) {
	executor.called = true
	executor.execution = execution
	if executor.mutateInput {
		execution.Source.Final[0] = 'X'
		execution.Source.Manifest[0] = 'X'
		execution.Source.Finding.Normalized[0] = 'X'
		execution.Source.Finding.Excerpt[0] = 'X'
		execution.Current.Bytes[0] = 'X'
		executor.execution = execution
	}
	if executor.cancel != nil {
		executor.cancel()
	}
	return executor.result, executor.err
}

func testVerifiedSource(t *testing.T) VerifiedSource {
	t.Helper()
	final := []byte(`{"review":"source"}`)
	manifest := []byte(`{"manifest":"source"}`)
	finding := []byte(`{"id":"F003"}`)
	excerpt := []byte("source excerpt")
	targetBytes := []byte("source target")
	return VerifiedSource{
		P2Verified: true, ProviderInstance: "fake.logic",
		SessionID: testSessionID(t),
		RunID:     testRunID(t, "r_019f596a-cfe4-7c9c-b82e-7149158243ba"),
		ReviewID:  testReviewID(t),
		Target:    testPatchIdentity(t, targetBytes),
		Finding: SourceFinding{
			ID: "F003", Role: domain.RoleLogic, Normalized: finding, Excerpt: excerpt,
		},
		Final: final, Manifest: manifest,
		Receipt: SourceReceipt{FinalSHA256: digest(final), ManifestSHA256: digest(manifest), FindingSHA256: digest(finding), ExcerptSHA256: digest(excerpt)},
	}
}

func testCurrentTarget(t *testing.T, bytes []byte) CurrentTarget {
	t.Helper()
	return CurrentTarget{Identity: testPatchIdentity(t, bytes), Bytes: append([]byte(nil), bytes...)}
}

func testPatchIdentity(t *testing.T, bytes []byte) domain.TargetIdentity {
	t.Helper()
	identity, err := domain.NewTargetIdentity(domain.TargetIdentityInput{Kind: domain.TargetPatch, SHA256: digest(bytes)})
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func testSessionID(t *testing.T) domain.SessionID {
	t.Helper()
	identity, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func testRunID(t *testing.T, value string) domain.RunID {
	t.Helper()
	identity, err := domain.ParseRunID(value)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func testReviewID(t *testing.T) domain.ReviewID {
	t.Helper()
	identity, err := domain.ParseReviewID("019f596a-cfe6-7c9c-b82e-7149158243ba")
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func testRequest(sourceRunID domain.RunID) Request {
	return Request{SourceRunID: sourceRunID, FindingID: "F003", Target: Target{Kind: TargetDirty, Value: "dirty"}}
}

func validExecutionResult(source VerifiedSource) ExecutionResult {
	return validExecutionResultWithExit(source, domain.ExitCommittedPass)
}

func validExecutionResultWithExit(source VerifiedSource, code domain.OperationalExitCode) ExecutionResult {
	schemaID, err := ports.ParseAssetID(validation.ProviderFollowupSchemaID)
	if err != nil {
		panic(err)
	}
	validator, err := validation.NewFollowupValidator(followupSchemaValidatorFunc(func(context.Context, ports.AssetID, []byte) error { return nil }), schemaID)
	if err != nil {
		panic(err)
	}
	output, err := validator.Validate(context.Background(), []byte(`{"schema_version":"mulgae-provider-followup-output.v1","summary":"resolved","resolution":"resolved","rationale":"verified","evidence":[{"current":{"path":"a.go","line_start":1,"line_end":1,"side":"head","quote":"x"}}],"new_findings":[],"limitations":[]}`), validation.FollowupValidationScope{
		SessionID: source.SessionID, SourceRunID: source.RunID, ReviewID: source.ReviewID,
		FindingID: source.Finding.ID, SourceTargetSHA256: source.Target.SHA256(),
		SourceExcerptSHA256: source.Receipt.ExcerptSHA256, CurrentTargetSHA256: source.Target.SHA256(),
		Role: source.Finding.Role, ProviderInstance: "fake.followup",
	})
	if err != nil {
		panic(err)
	}
	result, err := NewExecutionResult(
		source.SessionID, testRunIDForResult(), "https://mulgae.local/followup/review.json",
		output, mustFollowupCommittedExit(code),
	)
	if err != nil {
		panic(err)
	}
	return result
}

func testRunIDForResult() domain.RunID {
	identity, err := domain.ParseRunID("r_019f596a-cfe5-7c9c-b82e-7149158243ba")
	if err != nil {
		panic(err)
	}
	return identity
}

func mustFollowupService(t *testing.T, source SourceReader, capturer CurrentTargetCapturer, executor ChildExecutor) *Service {
	t.Helper()
	service, err := NewService(source, capturer, executor)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func assertFollowupErrorKind(t *testing.T, err error, want ErrorKind) {
	t.Helper()
	var workflowError *Error
	if !errors.As(err, &workflowError) || workflowError.Kind != want {
		t.Fatalf("error = %v, want %s", err, want)
	}
}

func mustFollowupCommittedExit(code domain.OperationalExitCode) domain.OperationalExitDecision {
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
