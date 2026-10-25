package publication

import "testing"

// publicationCountingScope enables the disabled-by-default publication
// verification counting seam for one sequential test. Tests using the scope
// must never call t.Parallel because the counters are process-global;
// package-level parallel tests only resume after every sequential test has
// completed.
type publicationCountingScope struct{}

// beginPublicationCounting enables counting, zeroes every counter, and
// restores the disabled state when the test ends.
func beginPublicationCounting(t *testing.T) publicationCountingScope {
	t.Helper()
	publicationVerificationCounting.Store(true)
	scope := publicationCountingScope{}
	scope.reset()
	t.Cleanup(func() {
		publicationVerificationCounting.Store(false)
		scope.reset()
	})
	return scope
}

// reset marks the boundary between fixture setup and the next measured
// operation.
func (scope publicationCountingScope) reset() {
	publicationDigestHelperCalls.Store(0)
	publicationEvidenceExcerptConstructions.Store(0)
	publicationAttemptArtifactConstructions.Store(0)
	publicationRoleReportConstructions.Store(0)
	publicationLiveSupportConstructions.Store(0)
}

// digests returns exact-byte digest helper calls made since the last reset.
func (scope publicationCountingScope) digests() int64 {
	return publicationDigestHelperCalls.Load()
}

// evidenceExcerpts returns evidence-excerpt artifacts constructed since the
// last reset.
func (scope publicationCountingScope) evidenceExcerpts() int64 {
	return publicationEvidenceExcerptConstructions.Load()
}

// attemptArtifacts returns attempt capture and status artifacts constructed
// since the last reset.
func (scope publicationCountingScope) attemptArtifacts() int64 {
	return publicationAttemptArtifactConstructions.Load()
}

// roleReports returns role-report artifacts constructed since the last reset.
func (scope publicationCountingScope) roleReports() int64 {
	return publicationRoleReportConstructions.Load()
}

// liveSupport returns live source metadata and binary evidence artifacts
// constructed since the last reset.
func (scope publicationCountingScope) liveSupport() int64 {
	return publicationLiveSupportConstructions.Load()
}
