package publication

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/app/evidence"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestPreparedCandidateRejectsMalformedAndUnvalidatedBuild(t *testing.T) {
	t.Parallel()
	candidate := PreparedCandidate{}
	if candidate.Valid() {
		t.Fatal("zero candidate is valid")
	}
	reviewID := publicationTestReviewID(t)
	validator := &publicationTestValidator{}
	if _, err := candidate.Build(context.Background(), validator, reviewID, publicationTestTime(), 1); err == nil {
		t.Fatal("Build accepted an unvalidated candidate")
	}
	if len(validator.ids) != 0 {
		t.Fatalf("validator saw %d schemas for invalid candidate", len(validator.ids))
	}

	valid := publicationTestCandidate(t, false)
	valid.roles[0].validFindingIDs = []string{"F002"}
	if valid.Valid() {
		t.Fatal("candidate with malformed finding binding is valid")
	}
	if _, err := valid.Build(context.Background(), validator, reviewID, publicationTestTime(), 1); err == nil {
		t.Fatal("Build accepted malformed candidate")
	}
}

func TestPreparedCandidateRejectsMismatchedExcerptIdentity(t *testing.T) {
	t.Parallel()
	candidate := publicationTestCandidate(t, true)
	candidate.findings[0].evidence[0].excerptSHA256 = "sha256:" + strings.Repeat("c", 64)
	if candidate.Valid() {
		t.Fatal("candidate accepted excerpt bytes that do not match the verified excerpt identity")
	}
}
func TestPublicationBundleRejectsFinalManifestOutcomeMismatch(t *testing.T) {
	t.Parallel()

	candidate := publicationTestCandidate(t, true)
	bundle, err := candidate.Build(
		context.Background(),
		&publicationTestValidator{},
		publicationTestReviewID(t),
		publicationTestTime(),
		1,
	)
	if err != nil {
		t.Fatal(err)
	}

	var manifest runManifestWire
	if err := json.Unmarshal(bundle.Manifest().Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.CIDecision = string(domain.CIPass)
	bytes, err := marshalCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	replaced, err := ports.NewImmutablePublicationArtifact(
		bundle.Manifest().Path(),
		sha256Identifier(bytes),
		bytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	bundle.manifest = replaced
	if bundle.Valid() {
		t.Fatal("bundle accepted a manifest whose CI axis differs from the final review")
	}
}
func TestPublicationBundleDerivesValidationStatusFromRepairedAttempts(t *testing.T) {
	t.Parallel()

	repaired := publicationTestCandidate(t, false)
	repaired.roles[0].repaired = true
	repairedBundle, err := repaired.Build(
		context.Background(),
		&publicationTestValidator{},
		publicationTestReviewID(t),
		publicationTestTime(),
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !repairedBundle.Valid() {
		t.Fatal("bundle with repaired final attempt is invalid")
	}

	var repairedManifest runManifestWire
	if err := json.Unmarshal(repairedBundle.Manifest().Bytes(), &repairedManifest); err != nil {
		t.Fatal(err)
	}
	repairedManifest.Attempts[0].ValidationState = "valid"
	repairedManifestBytes, err := marshalCanonical(repairedManifest)
	if err != nil {
		t.Fatal(err)
	}
	repairedManifestArtifact, err := ports.NewImmutablePublicationArtifact(
		repairedBundle.Manifest().Path(),
		sha256Identifier(repairedManifestBytes),
		repairedManifestBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	repairedBundle.manifest = repairedManifestArtifact
	if repairedBundle.Valid() {
		t.Fatal("bundle accepted repaired status without repaired attempt facts")
	}

	unrepaired := publicationTestCandidate(t, false)
	unrepairedBundle, err := unrepaired.Build(
		context.Background(),
		&publicationTestValidator{},
		publicationTestReviewID(t),
		publicationTestTime(),
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	var unrepairedManifest runManifestWire
	if err := json.Unmarshal(unrepairedBundle.Manifest().Bytes(), &unrepairedManifest); err != nil {
		t.Fatal(err)
	}
	unrepairedManifest.Attempts[0].ValidationState = "repaired_valid"
	unrepairedManifestBytes, err := marshalCanonical(unrepairedManifest)
	if err != nil {
		t.Fatal(err)
	}
	unrepairedManifestArtifact, err := ports.NewImmutablePublicationArtifact(
		unrepairedBundle.Manifest().Path(),
		sha256Identifier(unrepairedManifestBytes),
		unrepairedManifestBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	unrepairedBundle.manifest = unrepairedManifestArtifact
	if unrepairedBundle.Valid() {
		t.Fatal("bundle accepted valid status despite repaired attempt facts")
	}
}

func TestPublicationBundleRejectsUnderivedReportProjections(t *testing.T) {
	t.Parallel()

	candidate := publicationTestCandidate(t, true)
	bundle, err := candidate.Build(
		context.Background(),
		&publicationTestValidator{},
		publicationTestReviewID(t),
		publicationTestTime(),
		1,
	)
	if err != nil {
		t.Fatal(err)
	}

	var final finalReviewWire
	if err := json.Unmarshal(bundle.Final().Bytes(), &final); err != nil {
		t.Fatal(err)
	}
	final.CIReasonCodes = []string{"policy_evaluated"}
	final.Findings[0].Evidence[0].Current.Verification = "unverified"
	finalBytes, err := marshalCanonical(final)
	if err != nil {
		t.Fatal(err)
	}
	finalIdentity, err := ports.NewFinalReviewIdentity(
		bundle.Final().Identity().ReviewID(),
		bundle.Final().Identity().Path(),
		sha256Identifier(finalBytes),
	)
	if err != nil {
		t.Fatal(err)
	}
	finalArtifact, err := ports.NewFinalReviewArtifact(finalIdentity, finalBytes)
	if err != nil {
		t.Fatal(err)
	}
	bundle.final = finalArtifact
	if bundle.Valid() {
		t.Fatal("bundle accepted underived CI reasons and evidence projection")
	}

	bundle, err = candidate.Build(
		context.Background(),
		&publicationTestValidator{},
		publicationTestReviewID(t),
		publicationTestTime(),
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	tamperedExcerptBytes := []byte("tampered excerpt")
	tamperedExcerpt, err := ports.NewImmutablePublicationArtifact(
		bundle.Excerpts()[0].Path(),
		sha256Identifier(tamperedExcerptBytes),
		tamperedExcerptBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	bundle.excerpts[0] = tamperedExcerpt
	if bundle.Valid() {
		t.Fatal("bundle accepted an excerpt that does not match final evidence")
	}

	bundle, err = candidate.Build(
		context.Background(),
		&publicationTestValidator{},
		publicationTestReviewID(t),
		publicationTestTime(),
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	var manifest runManifestWire
	if err := json.Unmarshal(bundle.Manifest().Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Warnings = []string{"unexpected warning"}
	manifestBytes, err := marshalCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestArtifact, err := ports.NewImmutablePublicationArtifact(
		bundle.Manifest().Path(),
		sha256Identifier(manifestBytes),
		manifestBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	bundle.manifest = manifestArtifact
	if bundle.Valid() {
		t.Fatal("bundle accepted G006 manifest warnings")
	}
}

func TestPreparedCandidateRejectsNonCanonicalAttemptSequences(t *testing.T) {
	t.Parallel()
	fallbackID, err := domain.ParseAttemptID("a_019f596a-d049-79e7-b2b7-59822f012273")
	if err != nil {
		t.Fatal(err)
	}
	extraID, err := domain.ParseAttemptID("a_019f596a-d04a-79e7-b2b7-59822f012273")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*PreparedCandidate)
	}{
		{
			name: "fallback without primary",
			mutate: func(candidate *PreparedCandidate) {
				candidate.roles[0].attempts[0].kind = review.AttemptKindFallback
			},
		},
		{
			name: "fallback after successful primary",
			mutate: func(candidate *PreparedCandidate) {
				fallback := candidate.roles[0].attempts[0]
				fallback.id = fallbackID
				fallback.kind = review.AttemptKindFallback
				candidate.roles[0].attempts = append(candidate.roles[0].attempts, fallback)
			},
		},
		{
			name: "more than primary and fallback",
			mutate: func(candidate *PreparedCandidate) {
				candidate.roles[0].attempts[0].state = domain.AttemptFailed
				fallback := candidate.roles[0].attempts[0]
				fallback.id = fallbackID
				fallback.kind = review.AttemptKindFallback
				extra := fallback
				extra.id = extraID
				candidate.roles[0].attempts = append(candidate.roles[0].attempts, fallback, extra)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := publicationTestCandidate(t, false)
			test.mutate(&candidate)
			if candidate.Valid() {
				t.Fatal("candidate accepted a non-canonical attempt sequence")
			}
		})
	}
}
func publicationTestCandidate(t *testing.T, withFinding bool) PreparedCandidate {
	t.Helper()
	sessionID, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	if err != nil {
		t.Fatal(err)
	}
	logicAttempt, err := domain.ParseAttemptID("a_019f596a-d048-79e7-b2b7-59822f012273")
	if err != nil {
		t.Fatal(err)
	}
	securityAttempt, err := domain.ParseAttemptID("a_019f596a-d0ac-7c12-8b68-0bd73e911b2e")
	if err != nil {
		t.Fatal(err)
	}
	shaA := sha256Identifier([]byte("reviewed line\n"))
	excerptBytes := []byte("reviewed line\n")
	excerptClaim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{
		TargetSHA256: shaA,
		Side:         evidence.SideHead,
		Path:         "internal/app/review.go",
		LineStart:    1,
		LineEnd:      1,
		Quote:        string(excerptBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	excerptSHA256, err := excerptClaim.ExcerptSHA256(excerptBytes)
	if err != nil {
		t.Fatal(err)
	}
	roles := []preparedRole{
		{
			role: domain.RoleLogic, required: true, state: domain.RoleTaskSucceeded, valid: true, outcome: "completed",
			attempts: []preparedAttempt{{
				id: logicAttempt, kind: review.AttemptKindPrimary, provider: "kimi-logic", state: domain.AttemptSucceeded,
				invocations: []preparedInvocation{{sequence: 1, purpose: domain.InvocationInitial, state: domain.InvocationSucceeded}},
			}},
			validFindingIDs: []string{}, limitations: []string{},
		},
		{
			role: domain.RoleSecurity, required: true, state: domain.RoleTaskSucceeded, valid: true, outcome: "completed",
			attempts: []preparedAttempt{{
				id: securityAttempt, kind: review.AttemptKindPrimary, provider: "agy-security", state: domain.AttemptSucceeded,
				invocations: []preparedInvocation{{sequence: 1, purpose: domain.InvocationInitial, state: domain.InvocationSucceeded}},
			}},
			validFindingIDs: []string{}, limitations: []string{},
		},
	}
	candidate := PreparedCandidate{
		sessionID: sessionID,
		runID:     runID,
		runState:  domain.RunCompleted,
		target: preparedTarget{
			sha256: shaA,
		},
		threshold: domain.SeverityHigh,
		kar:       preparedKAR{version: "0.1.0", commit: "0123456789abcdef"},
		axes:      preparedAxes{content: domain.ContentNoFindings, coverage: domain.CoverageComplete, ci: domain.CIPass},
		roles:     roles,
		findings:  []preparedFinding{},
		failures:  []preparedFailure{},
		limits:    []string{},
		reasons:   []string{"policy_evaluated"},
		exitCode:  int(domain.ExitCommittedPass),
	}
	if withFinding {
		candidate.axes = preparedAxes{content: domain.ContentRequestChanges, coverage: domain.CoverageComplete, ci: domain.CIFail}
		candidate.reasons = []string{"request_changes_threshold"}
		candidate.exitCode = int(domain.ExitCommittedCIRejected)
		candidate.roles[0].validFindingIDs = []string{"F001"}
		candidate.findings = []preparedFinding{{
			id: "F001", fingerprint: "sha256:" + strings.Repeat("b", 64), role: domain.RoleLogic, provider: "kimi-logic",
			severity: domain.SeverityHigh, title: "Trusted finding", description: "The verifier accepted this evidence.",
			recommendation: "Correct the reviewed implementation.", confidence: domain.ConfidenceHigh, lifecycle: domain.FindingOpen,
			evidence: []preparedEvidence{{
				targetSHA256: shaA, side: evidence.SideHead, path: "internal/app/review.go", lineStart: 1, lineEnd: 1,
				quote: string(excerptBytes), excerptSHA256: excerptSHA256, excerpt: excerptBytes,
			}},
		}}
	}
	if err := candidate.validate(); err != nil {
		t.Fatalf("test candidate is not valid: %v", err)
	}
	return candidate
}

func publicationTestReviewID(t *testing.T) domain.ReviewID {
	t.Helper()
	id, err := domain.ParseReviewID("019f596a-d174-7321-b920-c2d312c82cc2")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func publicationTestTime() time.Time {
	return time.Date(2026, time.July, 13, 3, 0, 0, 500000000, time.UTC)
}
