package fakeprovider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	testAttemptID             = "a_018f0000-0000-7000-8000-000000000001"
	testSourceInvocationID    = "i_018f0000-0000-7000-8000-000000000002"
	testExecutionInvocationID = "018f0000-0000-7000-8000-000000000003"
)

func TestProviderConsumesMatchingCallAndOwnsFixtures(t *testing.T) {
	stdin := []byte("canonical prompt")
	stdout := []byte(`{"findings":[]}`)
	call := expectedCall(t, stdin, stdout)
	provider, err := New([]ExpectedCall{call})
	if err != nil {
		t.Fatal(err)
	}
	sameProvider, err := New([]ExpectedCall{call})
	if err != nil {
		t.Fatal(err)
	}

	stdout[0] = 'X'
	call.Result.Stdout[1] = 'X'
	result, err := provider.Invoke(context.Background(), invocation(t, call, stdin))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(result.Stdout()), `{"findings":[]}`; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if result.StdinByteLength() != len(stdin) {
		t.Fatalf("stdin byte length = %d, want %d", result.StdinByteLength(), len(stdin))
	}
	if got, want := result.CompleteStdinSHA256(), fakeProviderTestDigest(call.Stdin); got != want {
		t.Fatalf("stdin digest = %q, want %q", got, want)
	}
	sameResult, err := sameProvider.Invoke(context.Background(), invocation(t, call, stdin))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(sameResult.Stdout()), string(result.Stdout()); got != want {
		t.Fatalf("repeated construction stdout = %q, want %q", got, want)
	}

	resultBytes := result.Stdout()
	resultBytes[0] = 'X'
	if got, want := string(result.Stdout()), `{"findings":[]}`; got != want {
		t.Fatalf("stdout after caller mutation = %q, want %q", got, want)
	}

	transcript := provider.Transcript()
	if len(transcript) != 1 {
		t.Fatalf("transcript length = %d, want 1", len(transcript))
	}
	if got, want := transcript[0], expectedSummary(call); got != want {
		t.Fatalf("transcript = %#v, want %#v", got, want)
	}
	transcript[0].ProviderInstance = "mutated"
	if got := provider.Transcript()[0].ProviderInstance; got != call.ProviderInstance {
		t.Fatalf("transcript after caller mutation = %q, want %q", got, call.ProviderInstance)
	}
}

func TestProviderRejectsMismatchedIdentitiesWithoutConsumingScript(t *testing.T) {
	stdin := []byte("canonical prompt")
	call := expectedCall(t, stdin, []byte("first"))
	provider, err := New([]ExpectedCall{call})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		mutate func(ExpectedCall) ExpectedCall
	}{
		{
			name: "provider instance",
			mutate: func(actual ExpectedCall) ExpectedCall {
				actual.ProviderInstance = "other"
				return actual
			},
		},
		{
			name: "role",
			mutate: func(actual ExpectedCall) ExpectedCall {
				actual.Role = domain.RoleSecurity
				return actual
			},
		},
		{
			name: "purpose",
			mutate: func(actual ExpectedCall) ExpectedCall {
				actual.Purpose = ports.ProviderInvocationRepair
				return actual
			},
		},
		{
			name: "attempt ID",
			mutate: func(actual ExpectedCall) ExpectedCall {
				actual.AttemptID = mustAttemptID(t, "a_018f0000-0000-7000-8000-000000000004")
				return actual
			},
		},
		{
			name: "source invocation ID",
			mutate: func(actual ExpectedCall) ExpectedCall {
				actual.SourceInvocationID = "i_018f0000-0000-7000-8000-000000000005"
				return actual
			},
		},
		{
			name: "execution invocation ID",
			mutate: func(actual ExpectedCall) ExpectedCall {
				actual.ExecutionInvocationID = "018f0000-0000-7000-8000-000000000006"
				return actual
			},
		},
		{
			name: "stdin digest",
			mutate: func(actual ExpectedCall) ExpectedCall {
				actual.Stdin = bytesOfLength(t, len(actual.Stdin))
				return actual
			},
		},
		{
			name: "stdin length",
			mutate: func(actual ExpectedCall) ExpectedCall {
				actual.Stdin = bytesOfLength(t, len(actual.Stdin)+1)
				return actual
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			actual := test.mutate(call)
			_, err := provider.Invoke(context.Background(), invocation(t, actual, actual.Stdin))
			var unexpected *UnexpectedCallError
			if !errors.As(err, &unexpected) {
				t.Fatalf("error = %v, want UnexpectedCallError", err)
			}
			if expected, ok := unexpected.Expected(); !ok || expected != expectedSummary(call) {
				t.Fatalf("expected summary = %#v, present = %t", expected, ok)
			}
			if got, want := unexpected.Actual(), expectedSummary(actual); got != want {
				t.Fatalf("actual summary = %#v, want %#v", got, want)
			}
			if got := len(provider.Transcript()); got != 0 {
				t.Fatalf("transcript length after rejected call = %d, want 0", got)
			}
		})
	}

	result, err := provider.Invoke(context.Background(), invocation(t, call, stdin))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(result.Stdout()), "first"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

func TestProviderRejectsOutOfOrderAndExtraCalls(t *testing.T) {
	stdin := []byte("canonical prompt")
	first := expectedCall(t, stdin, []byte("first"))
	second := first
	second.Role = domain.RoleSecurity
	second.AttemptID = mustAttemptID(t, "a_018f0000-0000-7000-8000-000000000004")
	second.SourceInvocationID = "i_018f0000-0000-7000-8000-000000000005"
	second.ExecutionInvocationID = "018f0000-0000-7000-8000-000000000006"
	second.Result.Stdout = []byte("second")
	provider, err := New([]ExpectedCall{first, second})
	if err != nil {
		t.Fatal(err)
	}

	_, err = provider.Invoke(context.Background(), invocation(t, second, stdin))
	var unexpected *UnexpectedCallError
	if !errors.As(err, &unexpected) {
		t.Fatalf("out-of-order error = %v, want UnexpectedCallError", err)
	}
	if got := len(provider.Transcript()); got != 0 {
		t.Fatalf("transcript length after out-of-order call = %d, want 0", got)
	}

	if _, err := provider.Invoke(context.Background(), invocation(t, first, stdin)); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if _, err := provider.Invoke(context.Background(), invocation(t, second, stdin)); err != nil {
		t.Fatalf("second call: %v", err)
	}
	_, err = provider.Invoke(context.Background(), invocation(t, second, stdin))
	if !errors.As(err, &unexpected) {
		t.Fatalf("extra call error = %v, want UnexpectedCallError", err)
	}
	if _, ok := unexpected.Expected(); ok {
		t.Fatal("extra call unexpectedly reported a remaining expected call")
	}
}

func TestProviderReturnsScriptedErrorAndCancellationDoesNotConsumeScript(t *testing.T) {
	stdin := []byte("canonical prompt")
	call := expectedCall(t, stdin, nil)
	call.Result.Error = &ScriptError{Kind: ErrorKindUnavailable, Message: "offline"}
	provider, err := New([]ExpectedCall{call})
	if err != nil {
		t.Fatal(err)
	}
	call.Result.Error.Kind = ErrorKindRejected
	call.Result.Error.Message = "mutated"

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = provider.Invoke(ctx, invocation(t, call, stdin))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled invocation error = %v, want context.Canceled", err)
	}
	if got := len(provider.Transcript()); got != 0 {
		t.Fatalf("transcript length after canceled call = %d, want 0", got)
	}

	_, err = provider.Invoke(context.Background(), invocation(t, call, stdin))
	var scripted *ScriptError
	if !errors.As(err, &scripted) {
		t.Fatalf("scripted result error = %v, want ScriptError", err)
	}
	if scripted.Kind != ErrorKindUnavailable || scripted.Message != "offline" {
		t.Fatalf("scripted error = %#v", scripted)
	}
	if got := len(provider.Transcript()); got != 1 {
		t.Fatalf("transcript length after scripted error = %d, want 1", got)
	}
}

func TestNewRejectsInvalidScripts(t *testing.T) {
	stdin := []byte("canonical prompt")
	valid := expectedCall(t, stdin, []byte("stdout"))
	tests := []struct {
		name   string
		mutate func(ExpectedCall) ExpectedCall
	}{
		{
			name: "empty stdin",
			mutate: func(call ExpectedCall) ExpectedCall {
				call.Stdin = nil
				return call
			},
		},
		{
			name: "invalid expected provider identity",
			mutate: func(call ExpectedCall) ExpectedCall {
				call.ProviderInstance = "Invalid"
				return call
			},
		},
		{
			name: "stdout with scripted error",
			mutate: func(call ExpectedCall) ExpectedCall {
				call.Result.Error = &ScriptError{Kind: ErrorKindFailure}
				return call
			},
		},
		{
			name: "invalid scripted error kind",
			mutate: func(call ExpectedCall) ExpectedCall {
				call.Result.Stdout = nil
				call.Result.Error = &ScriptError{Kind: ErrorKind("bad")}
				return call
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New([]ExpectedCall{test.mutate(valid)}); err == nil {
				t.Fatal("New succeeded for invalid script")
			}
		})
	}
}

func expectedCall(t *testing.T, stdin, stdout []byte) ExpectedCall {
	t.Helper()
	return ExpectedCall{
		ProviderInstance:      "fixture",
		Role:                  domain.RoleLogic,
		Purpose:               ports.ProviderInvocationInitial,
		AttemptID:             mustAttemptID(t, testAttemptID),
		SourceInvocationID:    testSourceInvocationID,
		ExecutionInvocationID: testExecutionInvocationID,
		Stdin:                 append([]byte(nil), stdin...),
		Result: Result{
			Stdout: append([]byte(nil), stdout...),
		},
	}
}

func invocation(t *testing.T, call ExpectedCall, stdin []byte) ports.ProviderInvocation {
	t.Helper()
	invocation, err := ports.NewProviderInvocation(
		call.Role,
		call.ProviderInstance,
		call.AttemptID,
		call.Purpose,
		stdin,
		call.SourceInvocationID,
		call.ExecutionInvocationID,
		fakeProviderTestDigest(stdin),
	)
	if err != nil {
		t.Fatal(err)
	}
	return invocation
}

func expectedSummary(call ExpectedCall) CallSummary {
	return CallSummary{
		ProviderInstance:      call.ProviderInstance,
		Role:                  call.Role,
		Purpose:               call.Purpose,
		AttemptID:             call.AttemptID,
		SourceInvocationID:    call.SourceInvocationID,
		ExecutionInvocationID: call.ExecutionInvocationID,
		CompleteStdinSHA256:   fakeProviderTestDigest(call.Stdin),
		StdinByteLength:       len(call.Stdin),
	}
}

func bytesOfLength(t *testing.T, length int) []byte {
	t.Helper()
	if length <= 0 {
		t.Fatal("length must be positive")
	}
	return []byte(strings.Repeat("x", length))
}
func fakeProviderTestDigest(stdin []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("KAR-PROVIDER-STDIN/1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(stdin)
	return hex.EncodeToString(hash.Sum(nil))
}

func mustAttemptID(t *testing.T, value string) domain.AttemptID {
	t.Helper()
	attemptID, err := domain.ParseAttemptID(value)
	if err != nil {
		t.Fatal(err)
	}
	return attemptID
}
