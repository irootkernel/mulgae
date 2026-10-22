package ports

import "testing"

// verificationCountingScope enables the disabled-by-default verification
// counting seam for one sequential test. Tests using the scope must never call
// t.Parallel because the counters are process-global; package-level parallel
// tests only resume after every sequential test has completed.
type verificationCountingScope struct{}

// beginVerificationCounting enables counting, zeroes every counter, and
// restores the disabled state when the test ends.
func beginVerificationCounting(t *testing.T) verificationCountingScope {
	t.Helper()
	verificationCounting.Store(true)
	scope := verificationCountingScope{}
	scope.reset()
	t.Cleanup(func() {
		verificationCounting.Store(false)
		scope.reset()
	})
	return scope
}

// reset marks the boundary between fixture setup and the next measured
// operation.
func (scope verificationCountingScope) reset() {
	providerPacketDigestCalls.Store(0)
	sha256IdentifierCalls.Store(0)
	cloneBytesCalls.Store(0)
}

// packetDigests returns provider packet digests computed since the last reset.
func (scope verificationCountingScope) packetDigests() int64 {
	return providerPacketDigestCalls.Load()
}

// artifactDigests returns exact-byte artifact digests computed since the last
// reset.
func (scope verificationCountingScope) artifactDigests() int64 {
	return sha256IdentifierCalls.Load()
}

// copies returns defensive byte-copy helper calls made since the last reset.
func (scope verificationCountingScope) copies() int64 {
	return cloneBytesCalls.Load()
}
