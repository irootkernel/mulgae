// Package fakeprovider provides a deterministic scripted ReviewProvider for tests.
package fakeprovider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

var (
	// ErrNilContext reports an invocation made without a context.
	ErrNilContext = errors.New("fake provider: nil context")

	// ErrNilProvider reports an invocation on a nil Provider.
	ErrNilProvider = errors.New("fake provider: nil provider")
)

var _ ports.ReviewProvider = (*Provider)(nil)

// ErrorKind classifies a scripted provider error.
type ErrorKind string

const (
	// ErrorKindFailure is an unspecified deterministic provider failure.
	ErrorKindFailure ErrorKind = "failure"
	// ErrorKindUnavailable is a deterministic provider-unavailable failure.
	ErrorKindUnavailable ErrorKind = "unavailable"
	// ErrorKindRejected is a deterministic provider-rejected failure.
	ErrorKindRejected ErrorKind = "rejected"
)

// Valid reports whether kind is a supported scripted error kind.
func (kind ErrorKind) Valid() bool {
	switch kind {
	case ErrorKindFailure, ErrorKindUnavailable, ErrorKindRejected:
		return true
	default:
		return false
	}
}

// ScriptError is a typed, immutable-by-provider error returned by a scripted call.
type ScriptError struct {
	Kind    ErrorKind
	Message string
}

func (err *ScriptError) Error() string {
	if err == nil {
		return ""
	}
	if err.Message == "" {
		return "fake provider: " + string(err.Kind)
	}
	return "fake provider: " + string(err.Kind) + ": " + err.Message
}

// Result configures either stdout or a typed error for one expected call.
// Stdout and Error are mutually exclusive when Error is non-nil.
type Result struct {
	Stdout []byte
	Error  *ScriptError
}

// ExpectedCall describes one expected provider invocation in script order.
// New validates Stdin against the invocation contract, records only its integrity
// metadata, and does not retain the raw bytes.
type ExpectedCall struct {
	ProviderInstance      string
	Role                  domain.Role
	Purpose               ports.ProviderInvocationPurpose
	AttemptID             domain.AttemptID
	SourceInvocationID    string
	ExecutionInvocationID string
	Stdin                 []byte
	Result                Result
}

// CallSummary is a redacted provider-call transcript entry. It deliberately
// excludes raw stdin, stdout, and scripted error messages.
type CallSummary struct {
	ProviderInstance      string
	Role                  domain.Role
	Purpose               ports.ProviderInvocationPurpose
	AttemptID             domain.AttemptID
	SourceInvocationID    string
	ExecutionInvocationID string
	CompleteStdinSHA256   string
	StdinByteLength       int
}

// UnexpectedCallError reports an extra, out-of-order, or mismatched call.
// Its summaries remain redacted and cannot mutate Provider state.
type UnexpectedCallError struct {
	expected    CallSummary
	hasExpected bool
	actual      CallSummary
}

func (err *UnexpectedCallError) Error() string {
	if err == nil {
		return ""
	}
	if !err.hasExpected {
		return "fake provider: unexpected call after script exhaustion"
	}
	return "fake provider: unexpected or out-of-order call"
}

// Expected returns the next scripted call that rejected Actual. It reports
// false for an extra call after the script was exhausted.
func (err *UnexpectedCallError) Expected() (CallSummary, bool) {
	if err == nil || !err.hasExpected {
		return CallSummary{}, false
	}
	return err.expected, true
}

// Actual returns the redacted call that did not match the script.
func (err *UnexpectedCallError) Actual() CallSummary {
	if err == nil {
		return CallSummary{}
	}
	return err.actual
}

// Provider implements ports.ReviewProvider by consuming a fixed ordered script.
type Provider struct {
	mu     sync.Mutex
	script []scriptedCall
	next   int
	calls  []CallSummary
}

type scriptedCall struct {
	summary CallSummary
	stdout  []byte
	err     *scriptedError
}

type scriptedError struct {
	kind    ErrorKind
	message string
}

// New constructs a deterministic provider from an ordered script. It validates
// every expected identity and defensively copies mutable fixtures.
func New(script []ExpectedCall) (*Provider, error) {
	provider := &Provider{
		script: make([]scriptedCall, len(script)),
	}
	for index, call := range script {
		summary, err := validateExpectedCall(call)
		if err != nil {
			return nil, fmt.Errorf("fake provider script call %d: %w", index, err)
		}
		provider.script[index] = scriptedCall{
			summary: summary,
			stdout:  cloneBytes(call.Result.Stdout),
		}
		if call.Result.Error != nil {
			provider.script[index].err = &scriptedError{
				kind:    call.Result.Error.Kind,
				message: call.Result.Error.Message,
			}
		}
	}
	return provider, nil
}

// Invoke verifies and consumes exactly the next scripted call. A canceled
// context is returned before any script entry is consumed.
func (provider *Provider) Invoke(ctx context.Context, invocation ports.ProviderInvocation) (ports.ProviderResult, error) {
	if ctx == nil {
		return ports.ProviderResult{}, ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return ports.ProviderResult{}, err
	}
	if provider == nil {
		return ports.ProviderResult{}, ErrNilProvider
	}

	actual := callSummaryFromInvocation(invocation)
	provider.mu.Lock()
	defer provider.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return ports.ProviderResult{}, err
	}
	if provider.next >= len(provider.script) {
		return ports.ProviderResult{}, &UnexpectedCallError{actual: actual}
	}

	expected := provider.script[provider.next]
	if !expected.summary.equal(actual) {
		return ports.ProviderResult{}, &UnexpectedCallError{
			expected:    expected.summary,
			hasExpected: true,
			actual:      actual,
		}
	}

	provider.next++
	provider.calls = append(provider.calls, actual)
	if expected.err != nil {
		return ports.ProviderResult{}, &ScriptError{
			Kind:    expected.err.kind,
			Message: expected.err.message,
		}
	}

	result, err := ports.NewProviderResult(
		expected.stdout,
		actual.StdinByteLength,
		actual.CompleteStdinSHA256,
	)
	if err != nil {
		return ports.ProviderResult{}, fmt.Errorf("fake provider result: %w", err)
	}
	return result, nil
}

// Transcript returns caller-owned redacted summaries of calls consumed in
// invocation order.
func (provider *Provider) Transcript() []CallSummary {
	if provider == nil {
		return nil
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return append([]CallSummary(nil), provider.calls...)
}

func validateExpectedCall(call ExpectedCall) (CallSummary, error) {
	if call.Result.Error != nil {
		if len(call.Result.Stdout) != 0 {
			return CallSummary{}, fmt.Errorf("stdout and error are mutually exclusive")
		}
		if !call.Result.Error.Kind.Valid() {
			return CallSummary{}, fmt.Errorf("invalid scripted error kind %q", call.Result.Error.Kind)
		}
	}
	digest := stdinDigest(call.Stdin)
	invocation, err := ports.NewProviderInvocation(
		call.Role,
		call.ProviderInstance,
		call.AttemptID,
		call.Purpose,
		call.Stdin,
		call.SourceInvocationID,
		call.ExecutionInvocationID,
		digest,
	)
	if err != nil {
		return CallSummary{}, err
	}
	return callSummaryFromInvocation(invocation), nil
}

func callSummaryFromInvocation(invocation ports.ProviderInvocation) CallSummary {
	return CallSummary{
		ProviderInstance:      invocation.ProviderInstance(),
		Role:                  invocation.Role(),
		Purpose:               invocation.Purpose(),
		AttemptID:             invocation.AttemptID(),
		SourceInvocationID:    invocation.SourceInvocationID(),
		ExecutionInvocationID: invocation.ExecutionInvocationID(),
		CompleteStdinSHA256:   invocation.CompleteStdinSHA256(),
		StdinByteLength:       len(invocation.Stdin()),
	}
}

func (summary CallSummary) equal(other CallSummary) bool {
	return summary.ProviderInstance == other.ProviderInstance &&
		summary.Role == other.Role &&
		summary.Purpose == other.Purpose &&
		summary.AttemptID == other.AttemptID &&
		summary.SourceInvocationID == other.SourceInvocationID &&
		summary.ExecutionInvocationID == other.ExecutionInvocationID &&
		summary.CompleteStdinSHA256 == other.CompleteStdinSHA256 &&
		summary.StdinByteLength == other.StdinByteLength
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	clone := make([]byte, len(value))
	copy(clone, value)
	return clone
}
func stdinDigest(stdin []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("Mulgae-PROVIDER-STDIN/1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(stdin)
	return hex.EncodeToString(hash.Sum(nil))
}
