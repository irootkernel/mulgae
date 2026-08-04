package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestAttemptCaptureArtifactsAreImmutableAndSecretBytesAreDropped(t *testing.T) {
	t.Parallel()

	candidate := publicationTestCandidate(t, false)
	initial := []byte(`{"prompt":"initial"}`)
	capture, err := ports.NewCapturedAttemptArtifact(ports.AttemptArtifactInitialCandidate, initial, false)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := ports.NewCapturedAttemptArtifact(ports.AttemptArtifactStderr, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	attemptID := candidate.roles[0].attempts[0].id
	if err := candidate.bindAttemptArtifacts([]AttemptArtifactInput{
		{AttemptID: attemptID, InvocationSequence: 1, Artifact: capture},
		{AttemptID: attemptID, InvocationSequence: 1, Artifact: secret},
	}); err != nil {
		t.Fatal(err)
	}
	initial[0] = 'X'
	bundle, err := candidate.Build(
		context.Background(), publicationServiceValidator{}, publicationTestReviewID(t), publicationTestTime(), 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	var raw, status []byte
	for _, artifact := range bundle.Excerpts() {
		switch {
		case bytes.Contains([]byte(artifact.Path().String()), []byte("/candidate.initial.json")):
			raw = artifact.Bytes()
		case bytes.Contains([]byte(artifact.Path().String()), []byte("/attempts/"+attemptID.String()+"/status.json")):
			status = artifact.Bytes()
		}
	}
	if !bytes.Equal(raw, []byte(`{"prompt":"initial"}`)) {
		t.Fatalf("raw capture = %q, want defensive original", raw)
	}
	if len(status) == 0 || !bytes.Contains(status, []byte("security_rejected")) ||
		!bytes.Contains(status, []byte("/candidate.initial.json")) ||
		!bytes.Contains(status, []byte(sha256Identifier([]byte(`{"prompt":"initial"}`)))) {
		t.Fatalf("attempt status does not record canonical persisted and rejected captures: %s", status)
	}
	if bytes.Contains(status, []byte("secret")) || bytes.Contains(raw, []byte("secret")) {
		t.Fatal("security-rejected bytes were persisted")
	}
}
func TestFollowupRuntimeCapturesRequireExactObservedStreams(t *testing.T) {
	t.Parallel()

	candidate := []byte(`{"resolution":"no_change"}`)
	stdout := []byte("provider stdout")
	stderr := []byte("provider stderr")
	captures := make([]ports.CapturedAttemptArtifact, 0, 3)
	for _, stream := range []struct {
		kind  ports.AttemptArtifactKind
		bytes []byte
	}{
		{ports.AttemptArtifactInitialCandidate, candidate},
		{ports.AttemptArtifactStdout, stdout},
		{ports.AttemptArtifactStderr, stderr},
	} {
		capture, err := ports.NewCapturedAttemptArtifact(stream.kind, stream.bytes, false)
		if err != nil {
			t.Fatal(err)
		}
		captures = append(captures, capture)
	}
	if err := validateFollowupRuntimeCaptures(captures, candidate, stdout, stderr); err != nil {
		t.Fatalf("validate complete followup streams: %v", err)
	}
	if err := validateFollowupRuntimeCaptures(captures[:2], candidate, stdout, stderr); err == nil {
		t.Fatal("accepted missing followup stderr capture")
	}
}
func TestRunSupportContractRejectsArbitraryPathsAndRejectedSecretBytes(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	bytes := []byte("support")
	for _, value := range []string{
		fixture.run.SessionID().String() + "/" + fixture.run.RunID().String() + "/notes/support.raw",
		fixture.run.SessionID().String() + "/" + fixture.run.RunID().String() + "/excerpts/nested/F001_1.md",
		fixture.run.SessionID().String() + "/" + fixture.run.RunID().String() + "/attempts/not-an-attempt/status.json",
	} {
		path, err := ports.NewSafeRelativePath(value)
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := ports.NewImmutablePublicationArtifact(path, sha256Identifier(bytes), bytes)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ports.NewPersistRunSupportArtifactRequest(fixture.run, artifact); err == nil {
			t.Fatalf("arbitrary run-support path %q was accepted", value)
		}
	}
	if _, err := ports.NewCapturedAttemptArtifact(ports.AttemptArtifactStderr, []byte("secret"), true); err == nil {
		t.Fatal("security-rejected secret bytes were accepted")
	}
}
func TestRunSupportContractAcceptsOnlyCanonicalRuntimeInventoryPaths(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	bytes := []byte("runtime inventory")
	base := fixture.run.SessionID().String() + "/" + fixture.run.RunID().String() + "/"
	attemptID := publicationTestCandidate(t, false).roles[0].attempts[0].id.String()
	cases := []struct {
		path string
		kind ports.RunSupportArtifactKind
	}{
		{base + "target/target.bytes", ports.RunSupportArtifactTargetBytes},
		{base + "target/target-manifest.json", ports.RunSupportArtifactTargetManifest},
		{base + "prompts/" + attemptID + "/001-initial.stdin", ports.RunSupportArtifactPromptStdin},
		{base + "prompts/" + attemptID + "/001-initial.manifest.json", ports.RunSupportArtifactPromptManifest},
	}
	for _, test := range cases {
		path, err := ports.NewSafeRelativePath(test.path)
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := ports.NewImmutablePublicationArtifact(path, sha256Identifier(bytes), bytes)
		if err != nil {
			t.Fatal(err)
		}
		request, err := ports.NewPersistRunSupportArtifactRequest(fixture.run, artifact)
		if err != nil || request.Kind() != test.kind {
			t.Fatalf("runtime inventory path %q was not accepted as %q: %v", test.path, test.kind, err)
		}
	}
	for _, value := range []string{
		base + "target/other.bytes",
		base + "prompts/" + attemptID + "/1-initial.stdin",
		base + "prompts/" + attemptID + "/001-initial.json",
	} {
		path, err := ports.NewSafeRelativePath(value)
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := ports.NewImmutablePublicationArtifact(path, sha256Identifier(bytes), bytes)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ports.NewPersistRunSupportArtifactRequest(fixture.run, artifact); err == nil {
			t.Fatalf("non-canonical runtime inventory path %q was accepted", value)
		}
	}
}
func TestRepairedCandidateAndPatchStdoutHaveDistinctCanonicalArtifacts(t *testing.T) {
	t.Parallel()

	candidate := publicationTestCandidate(t, false)
	attempt := &candidate.roles[0].attempts[0]
	attempt.invocations = append(attempt.invocations, preparedInvocation{
		sequence: 2, purpose: domain.InvocationRepair, state: domain.InvocationSucceeded,
	})
	reconstructed := []byte(`{"schema_version":"mulgae-provider-review-output.v1","findings":[]}`)
	patch := []byte(`{"schema_version":"mulgae-repair-patch.v1","repairs":[]}`)
	repaired, err := ports.NewCapturedAttemptArtifact(ports.AttemptArtifactRepairedCandidate, reconstructed, false)
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := ports.NewCapturedAttemptArtifact(ports.AttemptArtifactStdout, patch, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := candidate.bindAttemptArtifacts([]AttemptArtifactInput{
		{AttemptID: attempt.id, InvocationSequence: 2, Artifact: repaired},
		{AttemptID: attempt.id, InvocationSequence: 2, Artifact: stdout},
	}); err != nil {
		t.Fatal(err)
	}
	bundle, err := candidate.Build(context.Background(), publicationServiceValidator{}, publicationTestReviewID(t), publicationTestTime(), 1)
	if err != nil {
		t.Fatal(err)
	}
	var candidateArtifact, stdoutArtifact []byte
	for _, artifact := range bundle.Excerpts() {
		switch artifact.Path().String() {
		case candidate.sessionID.String() + "/" + candidate.runID.String() + "/attempts/" + attempt.id.String() + "/candidate.repaired.001.json":
			candidateArtifact = artifact.Bytes()
		case candidate.sessionID.String() + "/" + candidate.runID.String() + "/attempts/" + attempt.id.String() + "/invocations/002-repair/stdout.raw":
			stdoutArtifact = artifact.Bytes()
		}
	}
	if !bytes.Equal(candidateArtifact, reconstructed) || !bytes.Equal(stdoutArtifact, patch) ||
		bytes.Equal(candidateArtifact, stdoutArtifact) {
		t.Fatalf("repaired candidate and patch stdout artifacts are not distinct: candidate=%q stdout=%q", candidateArtifact, stdoutArtifact)
	}
}

func TestAttemptCaptureAbsentPreservesRootPublicationBytes(t *testing.T) {
	t.Parallel()

	candidate := publicationTestCandidate(t, false)
	reviewID := publicationTestReviewID(t)
	legacy, err := candidate.Build(context.Background(), publicationServiceValidator{}, reviewID, publicationTestTime(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := candidate.bindAttemptArtifacts(nil); err != nil {
		t.Fatal(err)
	}
	withoutCapture, err := candidate.Build(context.Background(), publicationServiceValidator{}, reviewID, publicationTestTime(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(legacy.Final().Bytes(), withoutCapture.Final().Bytes()) ||
		!bytes.Equal(legacy.Manifest().Bytes(), withoutCapture.Manifest().Bytes()) {
		t.Fatal("root publication bytes changed without attempt capture")
	}
}
func TestChildPublicationLineageSerialization(t *testing.T) {
	t.Parallel()

	parent, err := domain.ParseRunID("r_019f596a-cf81-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	source, err := domain.ParseRunID("r_019f596a-cf82-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	sourceReview, err := domain.ParseReviewID("019f596a-cf83-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	finding := "F001"
	exact := ReplayModeExact
	cases := []struct {
		runType domain.RunType
		finding *string
		replay  *ReplayMode
	}{
		{runType: domain.RunTypeFollowup, finding: &finding},
		{runType: domain.RunTypeDelta},
		{runType: domain.RunTypeRerun, replay: &exact},
	}
	for _, test := range cases {
		childContext, err := NewChildPublicationContext(test.runType, parent, source, sourceReview, test.finding, test.replay)
		if err != nil {
			t.Fatal(err)
		}
		candidate := publicationTestCandidate(t, true)
		candidate.production = nil
		if test.runType == domain.RunTypeFollowup {
			for findingIndex := range candidate.findings {
				for evidenceIndex := range candidate.findings[findingIndex].evidence {
					item := &candidate.findings[findingIndex].evidence[evidenceIndex]
					item.sourceSessionID = candidate.sessionID.String()
					item.sourceRunID = source.String()
					item.sourceReviewID = sourceReview.String()
					item.sourceFindingID = finding
					item.sourceTargetSHA256 = candidate.target.sha256
					item.sourceExcerptSHA256 = item.currentExcerptSHA256
				}
			}
			candidate.followup = &preparedFollowupOutcome{
				resolution: domain.FollowupStillOpen,
				rationale:  "verified followup evidence",
				evidence:   append([]preparedEvidence(nil), candidate.findings[0].evidence...),
			}
		}
		child, err := domain.ParseRunID("r_019f596a-cf84-7c67-b265-f37053d51ccf")
		if err != nil {
			t.Fatal(err)
		}
		candidate.runID = child
		candidate.lineage = childContext.immutableLineage()
		bundle, err := candidate.Build(context.Background(), publicationServiceValidator{}, publicationTestReviewID(t), publicationTestTime(), 7)
		if err != nil {
			t.Fatal(err)
		}
		var final finalReviewWire
		var manifest runManifestWire
		var edge lineageEdgeWire
		if err := json.Unmarshal(bundle.Final().Bytes(), &final); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(bundle.Manifest().Bytes(), &manifest); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(bundle.LineageEdge().Bytes(), &edge); err != nil {
			t.Fatal(err)
		}
		if final.RunType != string(test.runType) || manifest.RunType != final.RunType ||
			final.ImmutableLineage.LineageEdgePath != bundle.LineageEdge().Path().String() ||
			final.ImmutableLineage.LineageEdgeSHA256 != bundle.LineageEdge().SHA256() ||
			!publicationLineageWireEqual(manifest.ImmutableLineage, final.ImmutableLineage) ||
			edge.ParentRunID == nil || *edge.ParentRunID != parent.String() ||
			edge.SourceRunID == nil || *edge.SourceRunID != source.String() ||
			edge.SourceReviewID == nil || *edge.SourceReviewID != sourceReview.String() ||
			!publicationOptionalStringEqual(edge.SourceFindingRef, test.finding) ||
			!publicationReplayModeEqual(edge.ReplayMode, test.replay) {
			t.Fatalf("child lineage serialization mismatch: %#v", final.ImmutableLineage)
		}
		evidence := final.Findings[0].Evidence[0]
		if evidence.Current.TargetSHA256 != final.Target.ContentSHA256 ||
			evidence.Current.Verification != "verified" {
			t.Fatalf("child current evidence view is inconsistent: %#v", evidence)
		}
		if test.runType == domain.RunTypeFollowup {
			if evidence.Source.SessionID != final.SessionID ||
				evidence.Source.RunID != source.String() ||
				evidence.Source.ReviewID != sourceReview.String() ||
				evidence.Source.FindingID != finding ||
				evidence.Source.SourceTargetSHA256 != final.Target.ContentSHA256 {
				t.Fatalf("followup source evidence view is inconsistent: %#v", evidence)
			}
		} else if evidence.Source.SessionID != final.SessionID ||
			evidence.Source.RunID != final.RunID ||
			evidence.Source.RunID == source.String() ||
			evidence.Source.ReviewID != final.ReviewID ||
			evidence.Source.FindingID != final.Findings[0].ID ||
			evidence.Source.SourceTargetSHA256 != final.Target.ContentSHA256 {
			t.Fatalf("child source evidence view is inconsistent: %#v", evidence)
		}
	}
}

func TestChildPublicationContextRejectsInvalidTruthTable(t *testing.T) {
	t.Parallel()

	runID, err := domain.ParseRunID("r_019f596a-cf81-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	reviewID, err := domain.ParseReviewID("019f596a-cf83-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	finding := "F001"
	if _, err := NewChildPublicationContext(domain.RunTypeFollowup, runID, runID, reviewID, nil, nil); err == nil {
		t.Fatal("followup without finding was accepted")
	}
	if _, err := NewChildPublicationContext(domain.RunTypeDelta, runID, runID, reviewID, &finding, nil); err == nil {
		t.Fatal("delta with finding was accepted")
	}
	if _, err := NewChildPublicationContext(domain.RunTypeRerun, runID, runID, reviewID, nil, nil); err == nil {
		t.Fatal("rerun without replay mode was accepted")
	}
}
func publicationLineageWireEqual(left, right immutableLineageWire) bool {
	return left.LineageEdgePath == right.LineageEdgePath &&
		left.LineageEdgeSHA256 == right.LineageEdgeSHA256 &&
		publicationOptionalStringEqual(left.ParentRunID, right.ParentRunID) &&
		publicationOptionalStringEqual(left.SourceRunID, right.SourceRunID) &&
		publicationOptionalStringEqual(left.SourceReviewID, right.SourceReviewID) &&
		publicationOptionalStringEqual(left.SourceFindingRef, right.SourceFindingRef) &&
		publicationOptionalStringEqual(left.ReplayMode, right.ReplayMode)
}

func publicationOptionalStringEqual(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
func publicationReplayModeEqual(left *string, right *ReplayMode) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == string(*right)
}

func TestRootPublicationBytesRemainLegacyCompatible(t *testing.T) {
	t.Parallel()

	root := publicationTestCandidate(t, false)
	legacyRoot := root
	legacyRoot.lineage = preparedLineage{}
	reviewID := publicationTestReviewID(t)
	createdAt := publicationTestTime()

	current, err := root.Build(context.Background(), publicationServiceValidator{}, reviewID, createdAt, 7)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := legacyRoot.Build(context.Background(), publicationServiceValidator{}, reviewID, createdAt, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current.Final().Bytes(), legacy.Final().Bytes()) ||
		!bytes.Equal(current.Manifest().Bytes(), legacy.Manifest().Bytes()) ||
		!bytes.Equal(current.LineageEdge().Bytes(), legacy.LineageEdge().Bytes()) ||
		!bytes.Equal(current.Epoch().Record().Bytes(), legacy.Epoch().Record().Bytes()) ||
		!bytes.Equal(current.Journal().Bytes(), legacy.Journal().Bytes()) ||
		!bytes.Equal(current.Status().Bytes(), legacy.Status().Bytes()) {
		t.Fatal("root publication bytes changed when no child context was supplied")
	}
}

const publicationServiceTestMaxBytes int64 = 8 << 20

func TestNewServiceRejectsNilAndTypedNilDependencies(t *testing.T) {
	t.Parallel()

	validator := publicationServiceValidator{}
	clock := publicationServiceClock{now: time.Date(2026, time.July, 16, 12, 0, 0, 0, time.UTC)}
	if service, err := NewService(nil, validator, clock, publicationServiceTestMaxBytes); err == nil || service != nil {
		t.Fatalf("NewService(nil, ...) = (%#v, %v), want nil service and error", service, err)
	}
	var typedNil *publicationServiceStore
	if service, err := NewService(typedNil, validator, clock, publicationServiceTestMaxBytes); err == nil || service != nil {
		t.Fatalf("NewService(typed nil, ...) = (%#v, %v), want nil service and error", service, err)
	}
	if service, err := NewService(&publicationServiceStore{}, validator, clock, 0); err == nil || service != nil {
		t.Fatalf("NewService(zero cap) = (%#v, %v), want nil service and error", service, err)
	}
}

func TestPublishRejectsInvalidCandidateBeforeIDIssuance(t *testing.T) {
	t.Parallel()

	store := &publicationServiceStore{}
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: time.Date(2026, time.July, 16, 12, 0, 0, 0, time.UTC)}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot("/tmp/publication-service")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Publish(context.Background(), root, PreparedCandidate{}, 1); err == nil {
		t.Fatal("Publish accepted an invalid candidate")
	}
	if store.issueCalls != 0 {
		t.Fatalf("IssueReviewID calls = %d, want 0", store.issueCalls)
	}
}

func TestPublishRejectsPreflightSchemaFailureBeforeIDIssuance(t *testing.T) {
	t.Parallel()

	store := &publicationServiceStore{}
	service, err := NewService(
		store,
		publicationServiceFailingValidator{},
		publicationServiceClock{now: publicationTestTime()},
		publicationServiceTestMaxBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot("/tmp/publication-service")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Publish(context.Background(), root, publicationTestCandidate(t, false), 1); err == nil {
		t.Fatal("Publish accepted a candidate whose preflight schema validation failed")
	}
	if store.issueCalls != 0 {
		t.Fatalf("IssueReviewID calls = %d, want 0", store.issueCalls)
	}
}

func TestPublishRejectsOversizePreflightBeforeIDIssuance(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	memberSizes := []int{
		len(fixture.bundle.Final().Bytes()),
		len(fixture.bundle.StagedFinal().Bytes()),
		len(fixture.bundle.Manifest().Bytes()),
		len(fixture.bundle.LineageEdge().Bytes()),
		len(fixture.bundle.Epoch().Record().Bytes()),
		len(fixture.bundle.Journal().Bytes()),
		len(fixture.bundle.Status().Bytes()),
	}
	for _, excerpt := range fixture.bundle.Excerpts() {
		memberSizes = append(memberSizes, len(excerpt.Bytes()))
	}
	maximum := 0
	for _, size := range memberSizes {
		if size > maximum {
			maximum = size
		}
	}
	if maximum < 2 {
		t.Fatalf("largest publication member = %d, want at least 2 bytes", maximum)
	}

	store := &publicationServiceStore{}
	service, err := NewService(
		store,
		publicationServiceValidator{},
		publicationServiceClock{now: publicationTestTime()},
		int64(maximum-1),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Publish(
		context.Background(),
		fixture.root,
		fixture.candidate,
		fixture.bundle.Epoch().Value(),
	); err == nil {
		t.Fatal("Publish accepted a preflight member above the configured cap")
	}
	if store.issueCalls != 0 {
		t.Fatalf("IssueReviewID calls = %d, want 0", store.issueCalls)
	}
}

func TestPublishPersistsAndPublishesInDurableOrder(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	result, err := service.Publish(context.Background(), fixture.root, fixture.candidate, fixture.bundle.Epoch().Value())
	if err != nil {
		t.Fatal(err)
	}
	if !publicationServiceCallsEqual(store.calls, []string{
		"issue", "candidate", "auxiliary", "read_auxiliary", "prepare", "journal", "stage", "journal", "install",
		"journal", "commit", "journal", "status", "journal", "observe",
	}) {
		t.Fatalf("publication calls = %#v", store.calls)
	}
	if len(store.candidateRequests) != 1 ||
		!bytes.Equal(store.candidateRequests[0].Candidate().Bytes(), fixture.bundle.Final().Bytes()) ||
		store.candidateRequests[0].Candidate().Identity() != fixture.bundle.Final().Identity() {
		t.Fatal("validated candidate persistence did not retain the issued final bytes")
	}
	if reviewID, ok := result.IssuedReviewID(); !ok || reviewID != fixture.issued {
		t.Fatalf("IssuedReviewID() = (%#v, %t), want (%#v, true)", reviewID, ok, fixture.issued)
	}
	if final, ok := result.Final(); !ok || final != fixture.bundle.Final().Identity() {
		t.Fatalf("Final() = (%#v, %t), want (%#v, true)", final, ok, fixture.bundle.Final().Identity())
	}
	if result.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatalf("authority = %q, want P2", result.Decision().Authority())
	}
	publicationServiceAssertJournalCAS(t, store.replacements)
}

func TestPublishP2ExitRetainsAllTerminalRoleAndPolicyReasons(t *testing.T) {
	t.Parallel()

	candidate := publicationTestCandidate(t, true)
	artistAttempt, err := domain.ParseAttemptID("a_019f596a-d110-7a47-aec7-c6a1ee8dc900")
	if err != nil {
		t.Fatal(err)
	}
	artist := clonePreparedRoles(candidate.roles[1:2])[0]
	artist.role = domain.RoleArtist
	artist.required = false
	artist.attempts[0].id = artistAttempt
	artist.attempts[0].provider = "agy-artist"
	artist.validFindingIDs = []string{"F001"}
	candidate.roles = append(candidate.roles, artist)
	candidate.findings[0].role = domain.RoleArtist
	candidate.findings[0].provider = "agy-artist"
	candidate.roles[0].validFindingIDs = nil

	for index, failure := range []struct {
		class  domain.FailureClass
		reason string
	}{
		{domain.FailureInvalidOutput, "provider_output_missing"},
		{domain.FailureProviderUnavailable, "provider_permission_denied"},
	} {
		role := &candidate.roles[index]
		role.state = domain.RoleTaskFailed
		role.valid = false
		role.outcome = "failed"
		role.failureClass = failure.class
		role.failureReason = failure.reason
		role.limitations = []string{"Role coverage is incomplete due to a terminal provider failure."}
		role.attempts[0].state = domain.AttemptFailed
		role.attempts[0].invocations[0].state = domain.InvocationFailed
		attemptID := role.attempts[0].id
		candidate.failures = append(candidate.failures, preparedFailure{
			class: failure.class, stage: "review", reason: failure.reason, attemptID: &attemptID,
		})
	}
	candidate.runState = domain.RunFailed
	candidate.axes = preparedAxes{content: domain.ContentRequestChanges, coverage: domain.CoverageIncomplete, ci: domain.CIFail}
	candidate.reasons = []string{"request_changes_threshold", "required_role_incomplete"}
	candidate.exitCode = int(domain.ExitIncompleteCoverage)
	candidate.limits = []string{"Required review coverage is incomplete."}
	agyArtist := candidate.production.Providers[0]
	agyArtist.Instance = "agy-artist"
	candidate.production.Providers = []ProductionProviderProvenance{
		agyArtist,
		candidate.production.Providers[0],
		candidate.production.Providers[1],
	}

	root, err := ports.NewAnchoredRoot("/tmp/publication-service")
	if err != nil {
		t.Fatal(err)
	}
	run, err := ports.NewPublicationRun(root, candidate.SessionID(), candidate.RunID())
	if err != nil {
		t.Fatal(err)
	}
	reviewID := publicationTestReviewID(t)
	bundle, err := candidate.Build(context.Background(), publicationServiceValidator{}, reviewID, publicationTestTime(), 1)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := ports.NewIssuedReviewID(reviewID, candidate.ValidatedCandidateSHA256())
	if err != nil {
		t.Fatal(err)
	}
	fixture := publicationServiceFixture{root: root, run: run, candidate: candidate, issued: issued, bundle: bundle}
	store := newPublicationServiceHappyStore(t, fixture)
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	result, err := service.Publish(context.Background(), root, candidate, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"provider_output_missing",
		"provider_permission_denied",
		"request_changes_threshold",
		"required_role_incomplete",
	}
	assertReasons := func(label string, result PublicationResult) {
		t.Helper()
		exit, ok := result.TerminalExit()
		if !ok || exit.Code() != domain.ExitIncompleteCoverage {
			t.Fatalf("%s terminal exit = (%#v, %t), want incomplete coverage", label, exit, ok)
		}
		got := make([]string, 0, len(exit.Reasons()))
		for _, reason := range exit.Reasons() {
			got = append(got, reason.ReasonCode())
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s P2 terminal reasons = %#v, want %#v", label, got, want)
		}
	}
	assertReasons("publish", result)

	recovered, err := service.Recover(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	assertReasons("recover", recovered)
}
func TestPublishNextUsesRootBoundEpochTransaction(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	store.withNextEpoch = func(ctx context.Context, root ports.AnchoredRoot, publish func(context.Context, uint64) error) error {
		if root != fixture.root {
			t.Fatalf("transaction root = %#v, want %#v", root, fixture.root)
		}
		return publish(ctx, fixture.bundle.Epoch().Value())
	}
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	result, err := service.PublishNext(context.Background(), fixture.root, fixture.candidate)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatalf("authority = %q, want P2", result.Decision().Authority())
	}
	if !publicationServiceCallsEqual(store.calls, []string{
		"next_epoch", "issue", "candidate", "auxiliary", "read_auxiliary", "prepare", "journal", "stage", "journal", "install",
		"journal", "commit", "journal", "status", "journal", "observe",
	}) {
		t.Fatalf("publication calls = %#v", store.calls)
	}
}

func TestPublishNextObservedReportsDurableLifecycle(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	store.withNextEpoch = func(ctx context.Context, root ports.AnchoredRoot, publish func(context.Context, uint64) error) error {
		return publish(ctx, fixture.bundle.Epoch().Value())
	}
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	observer := &publicationLifecycleRecorder{}

	result, err := service.PublishNextObserved(context.Background(), fixture.root, fixture.candidate, observer)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatalf("authority = %q, want P2", result.Decision().Authority())
	}
	observer.requireEvents(t, LifecyclePreparationStarted, LifecycleStaged, LifecycleInstalled, LifecycleCommitted)
}

func TestPublishNextObservedPersistenceFailureStopsBeforeInstall(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	store.withNextEpoch = func(ctx context.Context, root ports.AnchoredRoot, publish func(context.Context, uint64) error) error {
		return publish(ctx, fixture.bundle.Epoch().Value())
	}
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	observer := &publicationLifecycleRecorder{failOn: LifecycleStaged}

	returned, err := service.PublishNextObserved(context.Background(), fixture.root, fixture.candidate, observer)
	if err == nil {
		t.Fatal("PublishNextObserved succeeded after lifecycle persistence failure")
	}
	publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
	if returned.Decision().Authority() != "" {
		t.Fatalf("returned authority = %q, want no successful result alongside error", returned.Decision().Authority())
	}
	observer.requireEvents(t, LifecyclePreparationStarted, LifecycleStaged, LifecycleFailed)
	for _, call := range store.calls {
		if call == "install" {
			t.Fatal("publication installed a final after staged lifecycle persistence failed")
		}
	}
}

func TestPublishNextObservedCommittedPersistenceFailureRetainsP2Evidence(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	store.withNextEpoch = func(ctx context.Context, root ports.AnchoredRoot, publish func(context.Context, uint64) error) error {
		return publish(ctx, fixture.bundle.Epoch().Value())
	}
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	observer := &publicationLifecycleRecorder{failOn: LifecycleCommitted}

	returned, err := service.PublishNextObserved(context.Background(), fixture.root, fixture.candidate, observer)
	if err == nil {
		t.Fatal("PublishNextObserved succeeded after committed lifecycle persistence failure")
	}
	publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
	if returned.Decision().Authority() != "" {
		t.Fatalf("returned authority = %q, want failure result kept only as error evidence", returned.Decision().Authority())
	}
	committed, ok := committedPublicationResultFromError(err)
	if !ok || committed.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatalf("committed result = (%#v, %t), want retained P2 evidence", committed, ok)
	}
	snapshot, hasSnapshot := committed.Snapshot()
	if !hasSnapshot || !snapshot.Valid() || snapshot.Final().Identity() != fixture.bundle.Final().Identity() ||
		snapshot.Manifest().Path() != fixture.bundle.Manifest().Path() || snapshot.Manifest().SHA256() != fixture.bundle.Manifest().SHA256() {
		t.Fatal("committed diagnostic failure did not retain the authoritative snapshot")
	}
	manifestPath, hasManifestPath := CommittedPublicationManifestPathFromError(err)
	if !hasManifestPath || manifestPath != fixture.bundle.Manifest().Path() {
		t.Fatalf("committed manifest path = (%q, %t), want (%q, true)", manifestPath.String(), hasManifestPath, fixture.bundle.Manifest().Path().String())
	}
	observer.requireEvents(t, LifecyclePreparationStarted, LifecycleStaged, LifecycleInstalled, LifecycleCommitted)
}

func TestPublishNextRejectsStoreWithoutAtomicEpochTransaction(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	service, err := NewService(&publicationServiceStore{}, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.PublishNext(context.Background(), fixture.root, fixture.candidate); err == nil {
		t.Fatal("PublishNext accepted a store without atomic epoch transaction support")
	}
}

func TestPublishFollowupNextRejectsInvalidCandidateBeforeEpochTransaction(t *testing.T) {
	t.Parallel()

	store := &publicationServiceScriptedStore{}
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot("/tmp/publication-service")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.PublishFollowupNext(context.Background(), root, FollowupCandidateInput{}); err == nil {
		t.Fatal("PublishFollowupNext accepted an invalid candidate")
	}
	if len(store.calls) != 0 {
		t.Fatalf("publication calls = %#v, want validation before epoch transaction", store.calls)
	}
}

func TestPublishReturnsVerifiedPromptManifestIdentity(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceRuntimeFixture(t)
	attemptID := fixture.candidate.roles[0].attempts[0].id
	store := newPublicationServiceHappyStore(t, fixture)
	var rereadPromptManifest ports.ImmutablePublicationArtifact
	baseReadAuxiliary := store.readAuxiliary
	store.readAuxiliary = func(request ports.ReadAuxiliaryArtifactRequest) (ports.ImmutablePublicationArtifact, error) {
		artifact, err := baseReadAuxiliary(request)
		if err == nil && request.Kind() == ports.RunSupportArtifactPromptManifest &&
			strings.Contains(request.Path().String(), "/prompts/"+attemptID.String()+"/") {
			rereadPromptManifest = artifact
		}
		return artifact, err
	}
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	result, err := service.Publish(context.Background(), fixture.root, fixture.candidate, fixture.bundle.Epoch().Value())
	if err != nil {
		t.Fatal(err)
	}
	got, ok := result.PromptManifestArtifact(attemptID, 1)
	if !ok || got.Path() != rereadPromptManifest.Path() || got.SHA256() != rereadPromptManifest.SHA256() {
		t.Fatalf("PromptManifestArtifact() = (%#v, %t), want persisted/re-read %q/%q", got, ok, rereadPromptManifest.Path(), rereadPromptManifest.SHA256())
	}
	identities := result.PersistedRunSupportArtifacts()
	if len(identities) == 0 {
		t.Fatal("PersistedRunSupportArtifacts() omitted verified support artifacts")
	}
	identities[0] = RunSupportArtifactIdentity{}
	if _, ok := result.PromptManifestArtifact(attemptID, 1); !ok {
		t.Fatal("returned support identity slice aliases PublicationResult")
	}

	finalArtifact, err := ports.NewImmutablePublicationArtifact(
		fixture.bundle.Final().Identity().Path(),
		fixture.bundle.Final().Identity().SHA256(),
		fixture.bundle.Final().Bytes(),
	)
	if err != nil {
		t.Fatal(err)
	}
	result.supportArtifacts = []RunSupportArtifactIdentity{runSupportArtifactIdentity(finalArtifact)}
	if _, ok := result.PromptManifestArtifact(attemptID, 1); ok {
		t.Fatal("final-review identity substituted for prompt manifest")
	}
	result.supportArtifacts = nil
	if _, ok := result.PromptManifestArtifact(attemptID, 1); ok {
		t.Fatal("missing prompt manifest support identity was accepted")
	}
	result.supportArtifacts = []RunSupportArtifactIdentity{got, got}
	if _, ok := result.PromptManifestArtifact(attemptID, 1); ok {
		t.Fatal("ambiguous prompt manifest support identities were accepted")
	}
}
func TestRecoveredP2ResultsReturnVerifiedPromptManifestIdentity(t *testing.T) {
	for _, boundary := range []struct {
		name   string
		inject func(*publicationServiceScriptedStore)
	}{
		{
			name: "final install",
			inject: func(store *publicationServiceScriptedStore) {
				base := store.install
				store.install = func(request ports.InstallFinalRequest) (ports.InstallFinalResult, error) {
					result, err := base(request)
					return result, errors.Join(err, errors.New("install completion uncertain"))
				}
			},
		},
		{
			name: "composite commit",
			inject: func(store *publicationServiceScriptedStore) {
				base := store.commit
				store.commit = func(prepared ports.PreparedComposite) (ports.CompositeCommitResult, error) {
					result, err := base(prepared)
					return result, errors.Join(err, errors.New("commit completion uncertain"))
				}
			},
		},
		{
			name: "status replacement",
			inject: func(store *publicationServiceScriptedStore) {
				base := store.replace
				store.replace = func(request ports.MutableReplaceRequest) (ports.MutableReplaceResult, error) {
					result, err := base(request)
					if request.Document() == ports.MutablePublicationStatus {
						return result, errors.Join(err, errors.New("status completion uncertain"))
					}
					return result, err
				}
			},
		},
	} {
		t.Run(boundary.name, func(t *testing.T) {
			fixture := newPublicationServiceRuntimeFixture(t)
			attemptID := fixture.candidate.roles[0].attempts[0].id
			store := newPublicationServiceHappyStore(t, fixture)
			boundary.inject(store)
			service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.Publish(context.Background(), fixture.root, fixture.candidate, fixture.bundle.Epoch().Value())
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := result.PromptManifestArtifact(attemptID, 1); !ok {
				t.Fatal("recovered P2 result omitted verified prompt manifest")
			}
		})
	}

	t.Run("completed journal with runtime prompts", func(t *testing.T) {
		fixture := newPublicationServiceRuntimeFixture(t)
		attemptID := fixture.candidate.roles[0].attempts[0].id
		store := newPublicationServiceHappyStore(t, fixture)
		service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
		if err != nil {
			t.Fatal(err)
		}
		result, err := service.Recover(context.Background(), fixture.run)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := result.PromptManifestArtifact(attemptID, 1); !ok {
			t.Fatal("completed-journal P2 recovery omitted verified prompt manifest")
		}
	})

	t.Run("completed journal without runtime prompts", func(t *testing.T) {
		fixture := newPublicationServiceFixture(t)
		attemptID := fixture.candidate.roles[0].attempts[0].id
		store := newPublicationServiceHappyStore(t, fixture)
		service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
		if err != nil {
			t.Fatal(err)
		}
		result, err := service.Recover(context.Background(), fixture.run)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := result.PromptManifestArtifact(attemptID, 1); ok {
			t.Fatal("completed-journal P2 recovery invented a prompt manifest")
		}
		if got, want := len(result.PersistedRunSupportArtifacts()), len(fixture.bundle.SupportArtifacts()); got != want {
			t.Fatalf("recovered support identities = %d, want %d", got, want)
		}
	})
}
func TestRecoverCompletedJournalFailsClosedWhenBoundSupportCannotBeRead(t *testing.T) {
	failures := []struct {
		name  string
		match func(ports.ReadAuxiliaryArtifactRequest) bool
		read  func() (ports.ImmutablePublicationArtifact, error)
	}{
		{
			name: "missing support index",
			match: func(request ports.ReadAuxiliaryArtifactRequest) bool {
				return request.Kind() == ports.RunSupportArtifactSupportIndex
			},
			read: func() (ports.ImmutablePublicationArtifact, error) {
				return ports.ImmutablePublicationArtifact{}, fs.ErrNotExist
			},
		},
		{
			name: "corrupt support index",
			match: func(request ports.ReadAuxiliaryArtifactRequest) bool {
				return request.Kind() == ports.RunSupportArtifactSupportIndex
			},
			read: func() (ports.ImmutablePublicationArtifact, error) {
				return ports.ImmutablePublicationArtifact{}, nil
			},
		},
		{
			name: "missing selected prompt",
			match: func(request ports.ReadAuxiliaryArtifactRequest) bool {
				return request.Kind() == ports.RunSupportArtifactPromptManifest
			},
			read: func() (ports.ImmutablePublicationArtifact, error) {
				return ports.ImmutablePublicationArtifact{}, fs.ErrNotExist
			},
		},
		{
			name: "corrupt selected prompt",
			match: func(request ports.ReadAuxiliaryArtifactRequest) bool {
				return request.Kind() == ports.RunSupportArtifactPromptManifest
			},
			read: func() (ports.ImmutablePublicationArtifact, error) {
				return ports.ImmutablePublicationArtifact{}, nil
			},
		},
	}
	for _, failure := range failures {
		t.Run(failure.name, func(t *testing.T) {
			fixture := newPublicationServiceRuntimeFixture(t)
			store := newPublicationServiceHappyStore(t, fixture)
			baseRead := store.readAuxiliary
			store.readAuxiliary = func(request ports.ReadAuxiliaryArtifactRequest) (ports.ImmutablePublicationArtifact, error) {
				if failure.match(request) {
					return failure.read()
				}
				return baseRead(request)
			}
			service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
			if err != nil {
				t.Fatal(err)
			}

			result, recoverErr := service.Recover(context.Background(), fixture.run)
			publicationServiceRequireFailureClass(t, recoverErr, domain.FailureArtifact)
			if _, ok := result.Snapshot(); !ok {
				t.Fatal("completed-journal recovery discarded the committed snapshot after support corruption")
			}
			if _, ok := result.Final(); !ok {
				t.Fatal("completed-journal recovery discarded the final identity after support corruption")
			}
			if result.Decision().Authority() != domain.PublicationAuthorityP2 ||
				result.Decision().Status() != domain.PublicationCommitted {
				t.Fatal("completed-journal recovery downgraded durable P2 authority after support corruption")
			}
			if exit := result.Exit(); exit == nil || exit.Code() != domain.ExitArtifactFailure {
				t.Fatalf("completed-journal support corruption exit = %#v, want artifact failure", exit)
			}
		})
	}
}

func TestRecoveredP2FailsClosedWhenBoundSupportCannotBeRead(t *testing.T) {
	boundaries := []struct {
		name   string
		inject func(*publicationServiceScriptedStore, func())
	}{
		{
			name: "final install",
			inject: func(store *publicationServiceScriptedStore, arm func()) {
				base := store.install
				store.install = func(request ports.InstallFinalRequest) (ports.InstallFinalResult, error) {
					result, err := base(request)
					arm()
					return result, errors.Join(err, errors.New("install completion uncertain"))
				}
			},
		},
		{
			name: "composite commit",
			inject: func(store *publicationServiceScriptedStore, arm func()) {
				base := store.commit
				store.commit = func(prepared ports.PreparedComposite) (ports.CompositeCommitResult, error) {
					result, err := base(prepared)
					arm()
					return result, errors.Join(err, errors.New("commit completion uncertain"))
				}
			},
		},
		{
			name: "status replacement",
			inject: func(store *publicationServiceScriptedStore, arm func()) {
				base := store.replace
				store.replace = func(request ports.MutableReplaceRequest) (ports.MutableReplaceResult, error) {
					result, err := base(request)
					if request.Document() == ports.MutablePublicationStatus {
						arm()
						return result, errors.Join(err, errors.New("status completion uncertain"))
					}
					return result, err
				}
			},
		},
	}
	failures := []struct {
		name  string
		match func(ports.ReadAuxiliaryArtifactRequest) bool
		read  func() (ports.ImmutablePublicationArtifact, error)
	}{
		{
			name: "missing support index",
			match: func(request ports.ReadAuxiliaryArtifactRequest) bool {
				return request.Kind() == ports.RunSupportArtifactSupportIndex
			},
			read: func() (ports.ImmutablePublicationArtifact, error) {
				return ports.ImmutablePublicationArtifact{}, fs.ErrNotExist
			},
		},
		{
			name: "corrupt support index",
			match: func(request ports.ReadAuxiliaryArtifactRequest) bool {
				return request.Kind() == ports.RunSupportArtifactSupportIndex
			},
			read: func() (ports.ImmutablePublicationArtifact, error) {
				return ports.ImmutablePublicationArtifact{}, nil
			},
		},
		{
			name: "missing selected prompt",
			match: func(request ports.ReadAuxiliaryArtifactRequest) bool {
				return request.Kind() == ports.RunSupportArtifactPromptManifest
			},
			read: func() (ports.ImmutablePublicationArtifact, error) {
				return ports.ImmutablePublicationArtifact{}, fs.ErrNotExist
			},
		},
		{
			name: "corrupt selected prompt",
			match: func(request ports.ReadAuxiliaryArtifactRequest) bool {
				return request.Kind() == ports.RunSupportArtifactPromptManifest
			},
			read: func() (ports.ImmutablePublicationArtifact, error) {
				return ports.ImmutablePublicationArtifact{}, nil
			},
		},
	}
	for _, boundary := range boundaries {
		for _, failure := range failures {
			t.Run(boundary.name+"/"+failure.name, func(t *testing.T) {
				fixture := newPublicationServiceRuntimeFixture(t)
				store := newPublicationServiceHappyStore(t, fixture)
				armed := false
				baseRead := store.readAuxiliary
				store.readAuxiliary = func(request ports.ReadAuxiliaryArtifactRequest) (ports.ImmutablePublicationArtifact, error) {
					if armed && failure.match(request) {
						return failure.read()
					}
					return baseRead(request)
				}
				boundary.inject(store, func() { armed = true })
				service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
				if err != nil {
					t.Fatal(err)
				}

				result, err := service.Publish(context.Background(), fixture.root, fixture.candidate, fixture.bundle.Epoch().Value())
				if err == nil {
					t.Fatal("Publish returned committed success with unreadable manifest-bound support")
				}
				publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
				if _, ok := result.Snapshot(); !ok {
					t.Fatal("recovered P2 discarded its committed snapshot after support corruption")
				}
				if result.Decision().Authority() != domain.PublicationAuthorityP2 ||
					result.Decision().Status() != domain.PublicationCommitted {
					t.Fatal("recovered P2 downgraded durable authority after support corruption")
				}
			})
		}
	}
}

func TestPublishReconcilesValidIssuedIDReturnedWithError(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	baseIssue := store.issue
	store.issue = func(request ports.IssueReviewIDRequest) (ports.IssuedReviewID, error) {
		issued, err := baseIssue(request)
		if err != nil {
			return ports.IssuedReviewID{}, err
		}
		return issued, errors.New("issuance completion was uncertain")
	}
	service, err := NewService(
		store,
		publicationServiceValidator{},
		publicationServiceClock{now: publicationTestTime()},
		publicationServiceTestMaxBytes,
	)
	if err != nil {
		t.Fatal(err)
	}

	result, err := service.Publish(
		context.Background(),
		fixture.root,
		fixture.candidate,
		fixture.bundle.Epoch().Value(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if issued, ok := result.IssuedReviewID(); !ok || issued != fixture.issued {
		t.Fatalf("reconciled issued ID = (%#v, %t), want (%#v, true)", issued, ok, fixture.issued)
	}
	if len(store.issueRequests) != 1 || len(store.candidateRequests) != 0 ||
		!publicationServiceCallsEqual(store.calls, []string{"issue", "observe", "read_auxiliary"}) {
		t.Fatalf("ambiguous issuance calls = %#v, issue requests = %d, candidate requests = %d", store.calls, len(store.issueRequests), len(store.candidateRequests))
	}
}

func TestPublishReobservesValidMismatchedIssuedIDWithError(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	otherReviewID, err := domain.ParseReviewID("019f596a-d174-7321-b920-c2d312c82cc3")
	if err != nil {
		t.Fatal(err)
	}
	mismatchedIssued, err := ports.NewIssuedReviewID(otherReviewID, fixture.candidate.ValidatedCandidateSHA256())
	if err != nil {
		t.Fatal(err)
	}
	store := newPublicationServiceHappyStore(t, fixture)
	store.issue = func(ports.IssueReviewIDRequest) (ports.IssuedReviewID, error) {
		return mismatchedIssued, errors.New("issuance completion was uncertain")
	}
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Publish(context.Background(), fixture.root, fixture.candidate, fixture.bundle.Epoch().Value())
	publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
	if !publicationServiceCallsEqual(store.calls, []string{"issue", "observe"}) {
		t.Fatalf("mismatched issuance calls = %#v", store.calls)
	}
}

func TestPublishRejectsIssuedCandidateMismatchEvenWhenObservedP2MatchesIssuedID(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	staleCandidate := fixture.candidate
	staleCandidate.target.sha256 = sha256Identifier([]byte("stale target"))
	if !staleCandidate.Valid() ||
		staleCandidate.ValidatedCandidateSHA256() == fixture.candidate.ValidatedCandidateSHA256() {
		t.Fatal("test stale candidate is invalid or not distinct")
	}
	staleIssued, err := ports.NewIssuedReviewID(
		fixture.issued.ReviewID(),
		staleCandidate.ValidatedCandidateSHA256(),
	)
	if err != nil {
		t.Fatal(err)
	}
	staleBundle, err := staleCandidate.Build(
		context.Background(),
		publicationServiceValidator{},
		staleIssued.ReviewID(),
		publicationTestTime(),
		fixture.bundle.Epoch().Value(),
	)
	if err != nil {
		t.Fatal(err)
	}
	staleFixture := fixture
	staleFixture.candidate = staleCandidate
	staleFixture.issued = staleIssued
	staleFixture.bundle = staleBundle
	store := newPublicationServiceHappyStore(t, staleFixture)
	store.issue = func(ports.IssueReviewIDRequest) (ports.IssuedReviewID, error) {
		return staleIssued, errors.New("issuance completion was uncertain")
	}
	service, err := NewService(
		store,
		publicationServiceValidator{},
		publicationServiceClock{now: publicationTestTime()},
		publicationServiceTestMaxBytes,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Publish(
		context.Background(),
		fixture.root,
		fixture.candidate,
		fixture.bundle.Epoch().Value(),
	)
	publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
	if len(store.issueRequests) != 1 || len(store.candidateRequests) != 0 ||
		!publicationServiceCallsEqual(store.calls, []string{"issue", "observe"}) {
		t.Fatalf("stale P2 issuance calls = %#v", store.calls)
	}
}

func TestPublishDoesNotReissueAfterReconciledIssuanceBeforeBuildFailure(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	store.issue = func(ports.IssueReviewIDRequest) (ports.IssuedReviewID, error) {
		return fixture.issued, errors.New("issuance completion was uncertain")
	}
	store.observe = func() (ports.PublicationObservation, error) {
		return publicationServiceObservation(
			t,
			domain.JournalCollecting,
			domain.DurableObservationP0None,
			nil,
			nil,
			fixture.bundle.Epoch().Value(),
		), nil
	}
	validator := &publicationServiceFailAfterPreflightValidator{}
	service, err := NewService(store, validator, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Publish(context.Background(), fixture.root, fixture.candidate, fixture.bundle.Epoch().Value())
	publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
	if len(store.issueRequests) != 1 || !publicationServiceCallsEqual(store.calls, []string{"issue", "observe"}) {
		t.Fatalf("issuance/build failure calls = %#v, issue requests = %d", store.calls, len(store.issueRequests))
	}
}

func TestPublishReobservesValidMismatchedCandidateResultWithError(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	otherReviewID, err := domain.ParseReviewID("019f596a-d174-7321-b920-c2d312c82cc4")
	if err != nil {
		t.Fatal(err)
	}
	otherBundle, err := fixture.candidate.Build(
		context.Background(),
		publicationServiceValidator{},
		otherReviewID,
		publicationTestTime(),
		fixture.bundle.Epoch().Value(),
	)
	if err != nil {
		t.Fatal(err)
	}
	candidatePath, err := ports.ValidatedCandidatePath(fixture.run)
	if err != nil {
		t.Fatal(err)
	}
	receipt := publicationServiceReceipt(
		t,
		fixture.root,
		candidatePath,
		otherBundle.Final().Identity().SHA256(),
		len(otherBundle.Final().Bytes()),
	)
	mismatchedResult, err := ports.NewPersistValidatedCandidateResult(
		otherBundle.Final(),
		candidatePath,
		receipt,
		ports.ValidatedCandidateDurable,
	)
	if err != nil {
		t.Fatal(err)
	}
	store := newPublicationServiceHappyStore(t, fixture)
	store.persistCandidate = func(ports.PersistValidatedCandidateRequest) (ports.PersistValidatedCandidateResult, error) {
		return mismatchedResult, errors.New("candidate completion was uncertain")
	}
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	result, err := service.Publish(context.Background(), fixture.root, fixture.candidate, fixture.bundle.Epoch().Value())
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision().Authority() != domain.PublicationAuthorityP2 ||
		!publicationServiceCallsEqual(store.calls, []string{"issue", "candidate", "observe", "read_auxiliary"}) {
		t.Fatalf("mismatched candidate reconciliation = (%q, %#v)", result.Decision().Authority(), store.calls)
	}
}

func TestPublishUndurableCandidateReobservesWithoutFurtherPublication(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	store.persistCandidate = func(request ports.PersistValidatedCandidateRequest) (ports.PersistValidatedCandidateResult, error) {
		receipt := publicationServiceReceipt(t, fixture.root, request.Path(), request.Candidate().Identity().SHA256(), len(request.Candidate().Bytes()))
		result, err := ports.NewPersistValidatedCandidateResult(
			request.Candidate(), request.Path(), receipt, ports.ValidatedCandidateUndurable,
		)
		if err != nil {
			t.Fatal(err)
		}
		return result, errors.New("candidate directory sync failed")
	}
	store.observe = func() (ports.PublicationObservation, error) {
		return publicationServiceObservation(t, domain.JournalCollecting, domain.DurableObservationP0None, nil, nil, 1), nil
	}
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Publish(context.Background(), fixture.root, fixture.candidate, fixture.bundle.Epoch().Value())
	publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
	if !publicationServiceCallsEqual(store.calls, []string{"issue", "candidate", "observe"}) {
		t.Fatalf("publication calls after undurable candidate = %#v", store.calls)
	}
}

func TestPublishReobservesEveryValidPostEffectResult(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		inject    func(*publicationServiceScriptedStore)
		wantCalls []string
	}{
		{
			name: "validated candidate",
			inject: func(store *publicationServiceScriptedStore) {
				base := store.persistCandidate
				store.persistCandidate = func(request ports.PersistValidatedCandidateRequest) (ports.PersistValidatedCandidateResult, error) {
					result, err := base(request)
					if err != nil {
						return result, err
					}
					return result, errors.New("candidate post-effect uncertainty")
				}
			},
			wantCalls: []string{"issue", "candidate", "observe"},
		},
		{
			name: "prepared composite",
			inject: func(store *publicationServiceScriptedStore) {
				base := store.prepare
				store.prepare = func(request ports.PrepareCompositeRequest) (ports.PreparedComposite, error) {
					result, err := base(request)
					if err != nil {
						return result, err
					}
					return result, errors.New("prepare post-effect uncertainty")
				}
			},
			wantCalls: []string{"issue", "candidate", "auxiliary", "read_auxiliary", "prepare", "observe"},
		},
		{
			name: "journal replacement",
			inject: func(store *publicationServiceScriptedStore) {
				base := store.replace
				store.replace = func(request ports.MutableReplaceRequest) (ports.MutableReplaceResult, error) {
					result, err := base(request)
					if err != nil {
						return result, err
					}
					return result, errors.New("journal post-effect uncertainty")
				}
			},
			wantCalls: []string{"issue", "candidate", "auxiliary", "read_auxiliary", "prepare", "journal", "observe"},
		},
		{
			name: "staged final",
			inject: func(store *publicationServiceScriptedStore) {
				base := store.stage
				store.stage = func(request ports.StageFinalRequest) (ports.StageFinalResult, error) {
					result, err := base(request)
					if err != nil {
						return result, err
					}
					return result, errors.New("stage post-effect uncertainty")
				}
			},
			wantCalls: []string{"issue", "candidate", "auxiliary", "read_auxiliary", "prepare", "journal", "stage", "observe"},
		},
		{
			name: "installed final",
			inject: func(store *publicationServiceScriptedStore) {
				base := store.install
				store.install = func(request ports.InstallFinalRequest) (ports.InstallFinalResult, error) {
					result, err := base(request)
					if err != nil {
						return result, err
					}
					return result, errors.New("install post-effect uncertainty")
				}
			},
			wantCalls: []string{
				"issue", "candidate", "auxiliary", "read_auxiliary", "prepare", "journal", "stage", "journal",
				"install", "observe",
			},
		},
		{
			name: "composite commit",
			inject: func(store *publicationServiceScriptedStore) {
				base := store.commit
				store.commit = func(prepared ports.PreparedComposite) (ports.CompositeCommitResult, error) {
					result, err := base(prepared)
					if err != nil {
						return result, err
					}
					return result, errors.New("commit post-effect uncertainty")
				}
			},
			wantCalls: []string{
				"issue", "candidate", "auxiliary", "read_auxiliary", "prepare", "journal", "stage", "journal",
				"install", "journal", "commit", "observe",
			},
		},
		{
			name: "status replacement",
			inject: func(store *publicationServiceScriptedStore) {
				base := store.replace
				store.replace = func(request ports.MutableReplaceRequest) (ports.MutableReplaceResult, error) {
					result, err := base(request)
					if err != nil || request.Document() != ports.MutablePublicationStatus {
						return result, err
					}
					return result, errors.New("status post-effect uncertainty")
				}
			},
			wantCalls: []string{
				"issue", "candidate", "auxiliary", "read_auxiliary", "prepare", "journal", "stage", "journal",
				"install", "journal", "commit", "journal", "status", "observe",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPublicationServiceFixture(t)
			store := newPublicationServiceHappyStore(t, fixture)
			test.inject(store)
			service, err := NewService(
				store,
				publicationServiceValidator{},
				publicationServiceClock{now: publicationTestTime()},
				publicationServiceTestMaxBytes,
			)
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.Publish(
				context.Background(),
				fixture.root,
				fixture.candidate,
				fixture.bundle.Epoch().Value(),
			)
			if err != nil {
				t.Fatal(err)
			}
			if result.Decision().Authority() != domain.PublicationAuthorityP2 {
				t.Fatalf("authority = %q, want P2", result.Decision().Authority())
			}
			wantCalls := append(append([]string(nil), test.wantCalls...), "read_auxiliary")
			if !publicationServiceCallsEqual(store.calls, wantCalls) {
				t.Fatalf("calls = %#v, want %#v", store.calls, wantCalls)
			}
		})
	}
}

func TestPublishReobservesValidAuxiliaryPostEffectResult(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixtureWithFinding(t, true)
	if len(fixture.bundle.Excerpts()) == 0 {
		t.Fatal("finding fixture omitted publication excerpts")
	}
	store := newPublicationServiceHappyStore(t, fixture)
	base := store.persistAuxiliary
	store.persistAuxiliary = func(request ports.PersistAuxiliaryArtifactRequest) (ports.PersistAuxiliaryArtifactResult, error) {
		result, err := base(request)
		if err != nil {
			return result, err
		}
		return result, errors.New("auxiliary post-effect uncertainty")
	}
	service, err := NewService(
		store,
		publicationServiceValidator{},
		publicationServiceClock{now: publicationTestTime()},
		publicationServiceTestMaxBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Publish(
		context.Background(),
		fixture.root,
		fixture.candidate,
		fixture.bundle.Epoch().Value(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatalf("authority = %q, want P2", result.Decision().Authority())
	}
	want := []string{"issue", "candidate", "auxiliary", "observe"}
	for range fixture.bundle.SupportArtifacts() {
		want = append(want, "read_auxiliary")
	}
	if !publicationServiceCallsEqual(store.calls, want) {
		t.Fatalf("calls = %#v, want %#v", store.calls, want)
	}
}
func TestPublishPreventsP2WhenPersistedRunSupportCannotBeRead(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixtureWithFinding(t, true)
	store := newPublicationServiceHappyStore(t, fixture)
	store.readAuxiliary = func(ports.ReadAuxiliaryArtifactRequest) (ports.ImmutablePublicationArtifact, error) {
		return ports.ImmutablePublicationArtifact{}, errors.New("run support artifact is absent")
	}
	service, err := NewService(
		store,
		publicationServiceValidator{},
		publicationServiceClock{now: publicationTestTime()},
		publicationServiceTestMaxBytes,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.Publish(context.Background(), fixture.root, fixture.candidate, fixture.bundle.Epoch().Value()); err == nil {
		t.Fatal("Publish committed P2 with missing run support")
	}
	if want := []string{"issue", "candidate", "auxiliary", "read_auxiliary"}; !publicationServiceCallsEqual(store.calls, want) {
		t.Fatalf("calls = %#v, want %#v", store.calls, want)
	}
}

func TestPublishRejectsStageAndInstallReceiptLengthMismatches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		inject func(*publicationServiceScriptedStore, publicationServiceFixture)
	}{
		{
			name: "stage",
			inject: func(store *publicationServiceScriptedStore, fixture publicationServiceFixture) {
				store.stage = func(request ports.StageFinalRequest) (ports.StageFinalResult, error) {
					receipt, err := ports.NewSecureWriteReceipt(
						fixture.root,
						request.StagedPath(),
						request.Final().SHA256(),
						int64(len(fixture.bundle.Final().Bytes())+1),
						"publication",
						[]string{"validated_candidate"},
					)
					if err != nil {
						t.Fatal(err)
					}
					return ports.NewStageFinalResult(
						request.StagedPath(),
						request.Final(),
						receipt,
						ports.StageFinalDurable,
					)
				}
			},
		},
		{
			name: "install",
			inject: func(store *publicationServiceScriptedStore, fixture publicationServiceFixture) {
				store.install = func(request ports.InstallFinalRequest) (ports.InstallFinalResult, error) {
					receipt, err := ports.NewSecureWriteReceipt(
						fixture.root,
						request.Staged().Final().Path(),
						request.Staged().Final().SHA256(),
						int64(len(fixture.bundle.Final().Bytes())+1),
						"publication",
						[]string{"validated_candidate"},
					)
					if err != nil {
						t.Fatal(err)
					}
					return ports.NewInstallFinalResult(
						request.Staged().Final(),
						receipt,
						ports.InstallFinalDurable,
					)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPublicationServiceFixture(t)
			store := newPublicationServiceHappyStore(t, fixture)
			test.inject(store, fixture)
			service, err := NewService(
				store,
				publicationServiceValidator{},
				publicationServiceClock{now: publicationTestTime()},
				publicationServiceTestMaxBytes,
			)
			if err != nil {
				t.Fatal(err)
			}

			_, err = service.Publish(
				context.Background(),
				fixture.root,
				fixture.candidate,
				fixture.bundle.Epoch().Value(),
			)
			publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
		})
	}
}

func TestPublishStopsAtCancellationBoundaryAfterIDIssuance(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	ctx, cancel := context.WithCancel(context.Background())
	store.issue = func(request ports.IssueReviewIDRequest) (ports.IssuedReviewID, error) {
		cancel()
		return fixture.issued, nil
	}
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Publish(ctx, fixture.root, fixture.candidate, fixture.bundle.Epoch().Value())
	publicationServiceRequireFailureClass(t, err, domain.FailureCancelled)
	if !publicationServiceCallsEqual(store.calls, []string{"issue"}) {
		t.Fatalf("publication calls after cancellation = %#v", store.calls)
	}
}
func TestRecoverP0NoneHasNoTerminalExit(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	store := &publicationServiceScriptedStore{}
	store.observe = func() (ports.PublicationObservation, error) {
		return publicationServiceObservation(
			t,
			domain.JournalCollecting,
			domain.DurableObservationP0None,
			nil,
			nil,
			fixture.bundle.Epoch().Value(),
		), nil
	}
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	result, err := service.Recover(context.Background(), fixture.run)
	if err != nil {
		t.Fatal(err)
	}
	if result.Exit() != nil {
		t.Fatal("P0_NONE recovery exposed an operational exit")
	}
	if _, ok := result.TerminalExit(); ok {
		t.Fatal("P0_NONE recovery exposed a terminal exit decision")
	}
}
func TestP2ResultRejectsIssuedCandidateBindingMismatch(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	mismatchedIssued, err := ports.NewIssuedReviewID(
		fixture.issued.ReviewID(),
		sha256Identifier([]byte("different validation-bound candidate")),
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.p2Result(context.Background(), fixture.run, &mismatchedIssued, nil, nil)
	publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
	if !publicationServiceCallsEqual(store.calls, []string{"observe"}) {
		t.Fatalf("P2 binding mismatch calls = %#v", store.calls)
	}
}
func TestPublishRecoveredRejectsIssuedCandidateBindingMismatch(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	mismatchedIssued, err := ports.NewIssuedReviewID(
		fixture.issued.ReviewID(),
		sha256Identifier([]byte("different validation-bound candidate")),
	)
	if err != nil {
		t.Fatal(err)
	}

	result, recoverErr := service.publishRecovered(
		context.Background(),
		fixture.run,
		mismatchedIssued,
		fixture.bundle.Final().Identity(),
	)
	publicationServiceRequireFailureClass(t, recoverErr, domain.FailureArtifact)
	if exit := result.Exit(); exit == nil || exit.Code() != domain.ExitArtifactFailure {
		t.Fatalf("recovery binding mismatch exit = %#v, want artifact exit 7", exit)
	}
	if !publicationServiceCallsEqual(store.calls, []string{"observe", "read_auxiliary"}) {
		t.Fatalf("recovery binding mismatch calls = %#v", store.calls)
	}
}

func TestRecoverP2ReconstructionErrorOverridesStoredNormalExit(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	completedJournal := publicationServiceJournalForState(t, fixture.bundle.Journal(), domain.JournalCompleted)
	observedJournal, err := ports.NewObservedMutablePublicationDocument(
		ports.MutablePublicationJournal,
		completedJournal.Path(),
		completedJournal.SHA256(),
		completedJournal.Bytes(),
	)
	if err != nil {
		t.Fatal(err)
	}
	status := fixture.bundle.Status()
	invalidStatusBytes := []byte("{")
	observedStatus, err := ports.NewObservedMutablePublicationDocument(
		ports.MutablePublicationStatus,
		status.Path(),
		sha256Identifier(invalidStatusBytes),
		invalidStatusBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewPublicationRecoveryMaterialWithCommittedSnapshot(
		fixture.bundle.Final(),
		observedJournal,
		observedStatus,
		publicationServiceSnapshot(t, fixture.bundle),
	)
	if err != nil {
		t.Fatal(err)
	}
	store := newPublicationServiceHappyStore(t, fixture)
	store.replace = func(request ports.MutableReplaceRequest) (ports.MutableReplaceResult, error) {
		if request.Document() == ports.MutablePublicationStatus {
			return ports.MutableReplaceResult{}, errors.New("status write failed")
		}
		return ports.MutableReplaceResult{}, errors.New("unexpected mutable replacement")
	}
	store.observe = func() (ports.PublicationObservation, error) {
		return publicationServiceP2Observation(
			t,
			domain.JournalCompleted,
			domain.ExitCommittedPass,
			fixture.bundle.Epoch().Value(),
			material,
		), nil
	}
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	result, recoverErr := service.Recover(context.Background(), fixture.run)
	publicationServiceRequireFailureClass(t, recoverErr, domain.FailureArtifact)
	exit := result.Exit()
	if exit == nil || exit.Code() != domain.ExitArtifactFailure {
		t.Fatalf("errored P2 recovery exit = %#v, want artifact exit 7", exit)
	}
	if !publicationServiceCallsEqual(store.calls, []string{"observe", "read_auxiliary", "status"}) {
		t.Fatalf("errored P2 recovery calls = %#v", store.calls)
	}
}

func TestP2ResultRejectsSnapshotWarningsOutsidePolicy(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	var manifest runManifestWire
	if err := unmarshalCanonicalPublicationRecord(fixture.bundle.Manifest().Bytes(), &manifest, "manifest"); err != nil {
		t.Fatal(err)
	}
	manifest.Warnings = []string{"unexpected_warning"}
	manifestBytes, err := marshalCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	updatedManifest, err := ports.NewImmutablePublicationArtifact(
		fixture.bundle.Manifest().Path(),
		sha256Identifier(manifestBytes),
		manifestBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	var epochWire publicationEpochWire
	if err := unmarshalCanonicalPublicationRecord(fixture.bundle.Epoch().Record().Bytes(), &epochWire, "epoch"); err != nil {
		t.Fatal(err)
	}
	epochWire.Manifest.SHA256 = updatedManifest.SHA256()
	epochBytes, err := marshalCanonical(epochWire)
	if err != nil {
		t.Fatal(err)
	}
	updatedEpochRecord, err := ports.NewImmutablePublicationArtifact(
		fixture.bundle.Epoch().Record().Path(),
		sha256Identifier(epochBytes),
		epochBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	updatedEpoch, err := ports.NewPublicationEpoch(fixture.bundle.Epoch().Value(), updatedEpochRecord)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ports.NewCommittedPublicationSnapshot(
		fixture.bundle.Final(),
		updatedManifest,
		fixture.bundle.LineageEdge(),
		updatedEpoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	completedJournal := publicationServiceJournalForState(t, fixture.bundle.Journal(), domain.JournalCompleted)
	observedJournal, err := ports.NewObservedMutablePublicationDocument(
		ports.MutablePublicationJournal,
		completedJournal.Path(),
		completedJournal.SHA256(),
		completedJournal.Bytes(),
	)
	if err != nil {
		t.Fatal(err)
	}
	status := fixture.bundle.Status()
	observedStatus, err := ports.NewObservedMutablePublicationDocument(
		ports.MutablePublicationStatus,
		status.Path(),
		status.SHA256(),
		status.Bytes(),
	)
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewPublicationRecoveryMaterialWithCommittedSnapshot(
		fixture.bundle.Final(),
		observedJournal,
		observedStatus,
		snapshot,
	)
	if err != nil {
		t.Fatal(err)
	}
	store := newPublicationServiceHappyStore(t, fixture)
	store.observe = func() (ports.PublicationObservation, error) {
		return publicationServiceP2Observation(
			t,
			domain.JournalCompleted,
			domain.ExitCommittedPass,
			fixture.bundle.Epoch().Value(),
			material,
		), nil
	}
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.p2Result(context.Background(), fixture.run, nil, nil, nil)
	publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
	if !publicationServiceCallsEqual(store.calls, []string{"observe"}) {
		t.Fatalf("semantic snapshot rejection calls = %#v", store.calls)
	}
}

func TestRecoverForwardsExactCorruptionObservationCASFacts(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	reasons := []string{"hash_mismatch"}
	observation := publicationServiceObservation(
		t,
		domain.JournalCompleted,
		domain.DurableObservationAmbiguousOrMismatch,
		nil,
		reasons,
		fixture.bundle.Epoch().Value(),
	)
	store := &publicationServiceScriptedStore{}
	store.observe = func() (ports.PublicationObservation, error) { return observation, nil }
	store.diagnostic = func(request ports.CorruptionDiagnosticRequest) (ports.CorruptionDiagnosticResult, error) {
		if request.ObservationEpoch() != observation.StoreEpoch() ||
			!publicationServiceCallsEqual(request.ReasonCodes(), observation.ClassifierInput().AmbiguityReasons()) {
			return ports.CorruptionDiagnosticResult{}, errors.New("stale corruption observation")
		}
		receipt := publicationServiceReceipt(
			t,
			fixture.root,
			request.Diagnostic().Path(),
			request.Diagnostic().SHA256(),
			len(request.Diagnostic().Bytes()),
		)
		return ports.NewCorruptionDiagnosticResult(
			request.Diagnostic(),
			receipt,
			ports.CorruptionDiagnosticDurable,
		)
	}
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	result, recoverErr := service.Recover(context.Background(), fixture.run)
	publicationServiceRequireFailureClass(t, recoverErr, domain.FailureArtifact)
	if exit := result.Exit(); exit == nil || exit.Code() != domain.ExitArtifactFailure {
		t.Fatalf("corruption recovery exit = %#v, want artifact exit 7", exit)
	}
	if !publicationServiceCallsEqual(store.calls, []string{"observe", "diagnostic"}) {
		t.Fatalf("corruption recovery calls = %#v", store.calls)
	}
}

func TestRecoverRejectsCorruptionDiagnosticOverConfiguredByteLimit(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	observation := publicationServiceObservation(
		t,
		domain.JournalCompleted,
		domain.DurableObservationAmbiguousOrMismatch,
		nil,
		[]string{"hash_mismatch"},
		fixture.bundle.Epoch().Value(),
	)
	store := &publicationServiceScriptedStore{}
	store.observe = func() (ports.PublicationObservation, error) { return observation, nil }
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, 1)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Recover(context.Background(), fixture.run)
	publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
	if !publicationServiceCallsEqual(store.calls, []string{"observe"}) {
		t.Fatalf("oversize diagnostic calls = %#v", store.calls)
	}
}

func TestStoreFailureRetainsArtifactAndCancellationFacts(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := (&Service{}).storeFailure(ctx, "publication.store", "store write failed", errors.New("directory sync failed"))
	publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
	exit := publicationExitFromError(err)
	if exit == nil || exit.Code() != domain.ExitArtifactFailure {
		t.Fatalf("reduced exit = %#v, want artifact exit 7", exit)
	}
	if reasons := exit.Reasons(); len(reasons) != 2 ||
		reasons[0].Code() != domain.ExitArtifactFailure ||
		reasons[1].Code() != domain.ExitCancelled {
		t.Fatalf("retained exit reasons = %#v, want artifact and cancellation", reasons)
	}
}

func TestStoreFailureMapsTypedSecurityCauseToExitEight(t *testing.T) {
	t.Parallel()

	err := (&Service{}).storeFailure(
		context.Background(),
		"publication.store",
		"secure writer rejected candidate",
		publicationServiceClassifiedFailure{class: domain.FailureSecurityPolicy},
	)
	publicationServiceRequireFailureClass(t, err, domain.FailureSecurityPolicy)
	exit := publicationExitFromError(err)
	if exit == nil || exit.Code() != domain.ExitSecurityViolation {
		t.Fatalf("reduced exit = %#v, want security exit 8", exit)
	}
}

func TestRecoverAdoptsDurableStagedFinalBeforeInstall(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	prepared := publicationServicePreparedComposite(t, fixture.root, fixture.run, fixture.bundle)
	content := publicationServiceJournalForState(t, fixture.bundle.Journal(), domain.JournalContentValidated)
	staged := publicationServiceJournalForState(t, fixture.bundle.Journal(), domain.JournalFinalStaged)
	stagedPath, err := canonicalStagedFinalPath(fixture.run, fixture.bundle.Final().Identity())
	if err != nil {
		t.Fatal(err)
	}
	contentMaterial := publicationServiceRecoveryMaterial(t, fixture.bundle, content, nil, prepared)
	stagedMaterial := publicationServiceRecoveryMaterial(t, fixture.bundle, staged, &stagedPath, prepared)
	store := newPublicationServiceHappyStore(t, fixture)
	observations := []ports.PublicationObservation{
		publicationServiceObservationWithMaterial(t, domain.JournalContentValidated, domain.DurableObservationP0None, fixture.bundle.Epoch().Value(), contentMaterial),
		publicationServiceObservationWithMaterial(t, domain.JournalFinalStaged, domain.DurableObservationP0Staged, fixture.bundle.Epoch().Value(), stagedMaterial),
	}
	store.observe = func() (ports.PublicationObservation, error) {
		if len(observations) == 0 {
			return ports.PublicationObservation{}, errors.New("unexpected observation")
		}
		observation := observations[0]
		observations = observations[1:]
		return observation, nil
	}
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, int64(len(fixture.bundle.Final().Bytes())))
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Recover(context.Background(), fixture.run)
	publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
	if !publicationServiceCallsEqual(store.calls, []string{"observe", "stage", "journal", "observe", "adopt", "install", "observe"}) {
		t.Fatalf("recovery calls = %#v, error = %v", store.calls, err)
	}
	if len(store.stageBytes) != 1 || !bytes.Equal(store.stageBytes[0], fixture.bundle.Final().Bytes()) {
		t.Fatal("recovery staged bytes not equal to durable validated candidate bytes")
	}
	if len(store.issueRequests) != 0 || len(store.candidateRequests) != 0 || len(store.prepareRequests) != 0 {
		t.Fatal("recovery reconstructed publication material from caller state")
	}
}

func TestRecoverCommitsExactPreparedCompositeFromP1Installed(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	prepared := publicationServicePreparedComposite(t, fixture.root, fixture.run, fixture.bundle)
	installedJournal := publicationServiceJournalForState(
		t,
		fixture.bundle.Journal(),
		domain.JournalFinalFileInstalled,
	)
	p1Material := publicationServiceRecoveryMaterial(t, fixture.bundle, installedJournal, nil, prepared)
	completedJournal := publicationServiceJournalForState(t, fixture.bundle.Journal(), domain.JournalCompleted)
	p2Material := publicationServiceP2RecoveryMaterial(t, fixture.bundle, completedJournal)
	normalExit := domain.ExitCommittedPass
	observations := []ports.PublicationObservation{
		publicationServiceObservationWithMaterial(
			t,
			domain.JournalFinalFileInstalled,
			domain.DurableObservationP1Installed,
			fixture.bundle.Epoch().Value(),
			p1Material,
		),
		publicationServiceP2Observation(
			t,
			domain.JournalCompleted,
			normalExit,
			fixture.bundle.Epoch().Value(),
			p2Material,
		),
	}
	store := newPublicationServiceHappyStore(t, fixture)
	store.observe = func() (ports.PublicationObservation, error) {
		if len(observations) == 0 {
			return ports.PublicationObservation{}, errors.New("unexpected observation")
		}
		observation := observations[0]
		observations = observations[1:]
		return observation, nil
	}
	baseCommit := store.commit
	commitCalls := 0
	store.commit = func(actual ports.PreparedComposite) (ports.CompositeCommitResult, error) {
		commitCalls++
		if actual.Composite().Final() != prepared.Composite().Final() ||
			!sameImmutableArtifact(actual.StagedManifest(), prepared.StagedManifest()) ||
			!sameImmutableArtifact(actual.StagedLineageEdge(), prepared.StagedLineageEdge()) ||
			!sameImmutableArtifact(actual.StagedEpoch(), prepared.StagedEpoch()) {
			return ports.CompositeCommitResult{}, errors.New("recovery did not use exact persisted prepared members")
		}
		return baseCommit(actual)
	}
	service, err := NewService(
		store,
		publicationServiceValidator{},
		publicationServiceClock{now: publicationTestTime()},
		publicationServiceTestMaxBytes,
	)
	if err != nil {
		t.Fatal(err)
	}

	result, err := service.Recover(context.Background(), fixture.run)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision().Authority() != domain.PublicationAuthorityP2 || commitCalls != 1 ||
		!publicationServiceCallsEqual(store.calls, []string{"observe", "commit", "journal", "observe", "read_auxiliary"}) {
		t.Fatalf("P1 recovery = authority %q, commit calls %d, calls %#v", result.Decision().Authority(), commitCalls, store.calls)
	}
}

func TestRecoverReobservesValidAdoptionPostEffectResult(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	prepared := publicationServicePreparedComposite(t, fixture.root, fixture.run, fixture.bundle)
	stagedJournal := publicationServiceJournalForState(t, fixture.bundle.Journal(), domain.JournalFinalStaged)
	stagedPath, err := canonicalStagedFinalPath(fixture.run, fixture.bundle.Final().Identity())
	if err != nil {
		t.Fatal(err)
	}
	stagedMaterial := publicationServiceRecoveryMaterial(
		t,
		fixture.bundle,
		stagedJournal,
		&stagedPath,
		prepared,
	)
	completedJournal := publicationServiceJournalForState(t, fixture.bundle.Journal(), domain.JournalCompleted)
	p2Material := publicationServiceP2RecoveryMaterial(t, fixture.bundle, completedJournal)
	normalExit := domain.ExitCommittedPass
	observations := []ports.PublicationObservation{
		publicationServiceObservationWithMaterial(
			t,
			domain.JournalFinalStaged,
			domain.DurableObservationP0Staged,
			fixture.bundle.Epoch().Value(),
			stagedMaterial,
		),
		publicationServiceObservationWithMaterial(
			t,
			domain.JournalFinalStaged,
			domain.DurableObservationP0Staged,
			fixture.bundle.Epoch().Value(),
			stagedMaterial,
		),
		publicationServiceP2Observation(
			t,
			domain.JournalCompleted,
			normalExit,
			fixture.bundle.Epoch().Value(),
			p2Material,
		),
	}
	store := newPublicationServiceHappyStore(t, fixture)
	store.observe = func() (ports.PublicationObservation, error) {
		if len(observations) == 0 {
			return ports.PublicationObservation{}, errors.New("unexpected observation")
		}
		observation := observations[0]
		observations = observations[1:]
		return observation, nil
	}
	baseAdopt := store.adopt
	adoptCalls := 0
	store.adopt = func(request ports.AdoptStagedFinalRequest) (ports.StageFinalResult, error) {
		adoptCalls++
		result, err := baseAdopt(request)
		if err != nil || adoptCalls != 1 {
			return result, err
		}
		return result, errors.New("adoption post-effect uncertainty")
	}
	service, err := NewService(
		store,
		publicationServiceValidator{},
		publicationServiceClock{now: publicationTestTime()},
		publicationServiceTestMaxBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Recover(context.Background(), fixture.run)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatalf("authority = %q, want P2", result.Decision().Authority())
	}
	want := []string{"observe", "adopt", "observe", "adopt", "install", "observe", "read_auxiliary"}
	if !publicationServiceCallsEqual(store.calls, want) {
		t.Fatalf("calls = %#v, want %#v", store.calls, want)
	}
}
func TestRecoverRejectsMismatchedPreIDCandidateBinding(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	prepared := publicationServicePreparedComposite(t, fixture.root, fixture.run, fixture.bundle)
	content := publicationServiceJournalForState(t, fixture.bundle.Journal(), domain.JournalContentValidated)
	mismatched := publicationServiceJournalWithCandidateHash(
		t,
		content,
		sha256Identifier([]byte("different pre-ID candidate")),
	)
	material := publicationServiceRecoveryMaterial(t, fixture.bundle, mismatched, nil, prepared)
	store := &publicationServiceScriptedStore{}
	store.observe = func() (ports.PublicationObservation, error) {
		return publicationServiceObservationWithMaterial(
			t,
			domain.JournalContentValidated,
			domain.DurableObservationP0None,
			fixture.bundle.Epoch().Value(),
			material,
		), nil
	}
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Recover(context.Background(), fixture.run)
	publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
	if !publicationServiceCallsEqual(store.calls, []string{"observe"}) {
		t.Fatalf("recovery calls = %#v, want only observation before mismatch rejection", store.calls)
	}
}

func TestRecoverNamedCrossBoundaryCorruptionOnlyWritesDiagnostic(t *testing.T) {
	t.Parallel()

	cases := []string{
		"pub-cross-content-validated-staged-temp",
		"pub-cross-final-staged-installed-final",
		"pub-cross-final-installed-composite-commit",
		"pub-cross-manifest-committed-completed-side-effect",
		"pub-cross-hint-low-valid-p2",
		"pub-cross-staged-and-installed-conflict",
		"pub-cross-p2-manifest-edge-mismatch",
		"pub-cross-completed-missing-final",
		"pub-cross-final-installed-no-journal",
		"pub-cross-p0-none-impossible-high-hint",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := newPublicationServiceFixture(t)
			store := &publicationServiceScriptedStore{}
			store.observe = func() (ports.PublicationObservation, error) {
				observationClass := domain.DurableObservationAmbiguousOrMismatch
				reasons := []string{"cross_boundary_corrupt"}
				if name == "pub-cross-p0-none-impossible-high-hint" {
					observationClass = domain.DurableObservationP0None
					reasons = nil
				}
				return publicationServiceObservation(
					t,
					domain.JournalCompleted,
					observationClass,
					nil,
					reasons,
					fixture.bundle.Epoch().Value(),
				), nil
			}
			store.diagnostic = func(request ports.CorruptionDiagnosticRequest) (ports.CorruptionDiagnosticResult, error) {
				wantReasons := []string{"cross_boundary_corrupt"}
				if name == "pub-cross-p0-none-impossible-high-hint" {
					wantReasons = []string{"missing_required_durable_effect"}
				}
				if !publicationServiceCallsEqual(request.ReasonCodes(), wantReasons) {
					return ports.CorruptionDiagnosticResult{}, errors.New("corruption reasons do not match classifier decision")
				}
				receipt := publicationServiceReceipt(
					t,
					fixture.root,
					request.Diagnostic().Path(),
					request.Diagnostic().SHA256(),
					len(request.Diagnostic().Bytes()),
				)
				return ports.NewCorruptionDiagnosticResult(
					request.Diagnostic(), receipt, ports.CorruptionDiagnosticDurable,
				)
			}
			service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
			if err != nil {
				t.Fatal(err)
			}

			result, recoverErr := service.Recover(context.Background(), fixture.run)
			publicationServiceRequireFailureClass(t, recoverErr, domain.FailureArtifact)
			if result.Exit().Code() != domain.ExitArtifactFailure {
				t.Fatalf("exit = %d, want 7", result.Exit().Code())
			}
			if !publicationServiceCallsEqual(store.calls, []string{"observe", "diagnostic"}) {
				t.Fatalf("cross-boundary recovery calls = %#v", store.calls)
			}
		})
	}
}
func TestRecoverCorruptionDiagnosticIsIdempotentByEpochAndBytes(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	store := &publicationServiceScriptedStore{}
	corrupt := publicationServiceObservation(
		t,
		domain.JournalCompleted,
		domain.DurableObservationAmbiguousOrMismatch,
		nil,
		[]string{"hash_mismatch"},
		fixture.bundle.Epoch().Value(),
	)
	store.observe = func() (ports.PublicationObservation, error) { return corrupt, nil }
	store.diagnostic = func(request ports.CorruptionDiagnosticRequest) (ports.CorruptionDiagnosticResult, error) {
		receipt := publicationServiceReceipt(
			t,
			fixture.root,
			request.Diagnostic().Path(),
			request.Diagnostic().SHA256(),
			len(request.Diagnostic().Bytes()),
		)
		result, err := ports.NewCorruptionDiagnosticResult(
			request.Diagnostic(), receipt, ports.CorruptionDiagnosticDurable,
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(store.diagnosticRequests) > 1 {
			return ports.CorruptionDiagnosticResult{}, errors.New("diagnostic already exists")
		}
		return result, nil
	}
	service, err := NewService(store, publicationServiceValidator{}, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	for attempt := 0; attempt < 2; attempt++ {
		result, recoverErr := service.Recover(context.Background(), fixture.run)
		publicationServiceRequireFailureClass(t, recoverErr, domain.FailureArtifact)
		if result.Exit().Code() != domain.ExitArtifactFailure {
			t.Fatalf("attempt %d exit = %d, want 7", attempt, result.Exit().Code())
		}
	}
	if len(store.diagnosticRequests) != 2 {
		t.Fatalf("diagnostic requests = %d, want 2", len(store.diagnosticRequests))
	}
	first := store.diagnosticRequests[0]
	second := store.diagnosticRequests[1]
	if first.ObservationEpoch() != second.ObservationEpoch() ||
		first.Diagnostic().Path() != second.Diagnostic().Path() ||
		first.Diagnostic().SHA256() != second.Diagnostic().SHA256() ||
		!bytes.Equal(first.Diagnostic().Bytes(), second.Diagnostic().Bytes()) {
		t.Fatal("corruption diagnostic retry changed its immutable identity or bytes")
	}
}

func TestRecoverReobservesValidDiagnosticPostEffectResult(t *testing.T) {
	t.Parallel()

	fixture := newPublicationServiceFixture(t)
	store := &publicationServiceScriptedStore{}
	corrupt := publicationServiceObservation(
		t,
		domain.JournalCompleted,
		domain.DurableObservationAmbiguousOrMismatch,
		nil,
		[]string{"hash_mismatch"},
		fixture.bundle.Epoch().Value(),
	)
	store.observe = func() (ports.PublicationObservation, error) { return corrupt, nil }
	store.diagnostic = func(request ports.CorruptionDiagnosticRequest) (ports.CorruptionDiagnosticResult, error) {
		receipt := publicationServiceReceipt(
			t,
			fixture.root,
			request.Diagnostic().Path(),
			request.Diagnostic().SHA256(),
			len(request.Diagnostic().Bytes()),
		)
		result, err := ports.NewCorruptionDiagnosticResult(
			request.Diagnostic(),
			receipt,
			ports.CorruptionDiagnosticDurable,
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(store.diagnosticRequests) == 1 {
			return result, errors.New("diagnostic post-effect uncertainty")
		}
		return result, nil
	}
	service, err := NewService(
		store,
		publicationServiceValidator{},
		publicationServiceClock{now: publicationTestTime()},
		publicationServiceTestMaxBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, recoverErr := service.Recover(context.Background(), fixture.run)
	publicationServiceRequireFailureClass(t, recoverErr, domain.FailureArtifact)
	if result.Exit().Code() != domain.ExitArtifactFailure {
		t.Fatalf("exit = %d, want 7", result.Exit().Code())
	}
	want := []string{"observe", "diagnostic", "observe", "diagnostic"}
	if !publicationServiceCallsEqual(store.calls, want) {
		t.Fatalf("calls = %#v, want %#v", store.calls, want)
	}
}

type publicationServiceValidator struct{}

func (publicationServiceValidator) Validate(context.Context, ports.AssetID, []byte) error { return nil }

type publicationServiceClock struct{ now time.Time }

func (clock publicationServiceClock) Now() time.Time { return clock.now }

type publicationServiceStore struct{ issueCalls int }

func (store *publicationServiceStore) IssueReviewID(context.Context, ports.IssueReviewIDRequest) (ports.IssuedReviewID, error) {
	store.issueCalls++
	return ports.IssuedReviewID{}, errors.New("unexpected issue")
}

func (*publicationServiceStore) ResolveRun(context.Context, ports.ResolvePublicationRunRequest) (ports.PublicationRun, error) {
	return ports.PublicationRun{}, errors.New("unexpected resolve")
}

func (*publicationServiceStore) ObserveRun(context.Context, ports.ObserveRunRequest) (ports.PublicationObservation, error) {
	return ports.PublicationObservation{}, errors.New("unexpected observe")
}

func (*publicationServiceStore) PersistValidatedCandidate(context.Context, ports.PersistValidatedCandidateRequest) (ports.PersistValidatedCandidateResult, error) {
	return ports.PersistValidatedCandidateResult{}, errors.New("unexpected candidate persistence")
}

func (*publicationServiceStore) PersistAuxiliaryArtifact(context.Context, ports.PersistAuxiliaryArtifactRequest) (ports.PersistAuxiliaryArtifactResult, error) {
	return ports.PersistAuxiliaryArtifactResult{}, errors.New("unexpected auxiliary persistence")
}

func (*publicationServiceStore) ReadAuxiliaryArtifact(context.Context, ports.ReadAuxiliaryArtifactRequest) (ports.ImmutablePublicationArtifact, error) {
	return ports.ImmutablePublicationArtifact{}, errors.New("unexpected auxiliary read")
}

func (*publicationServiceStore) PrepareComposite(context.Context, ports.PrepareCompositeRequest) (ports.PreparedComposite, error) {
	return ports.PreparedComposite{}, errors.New("unexpected preparation")
}

func (*publicationServiceStore) StageFinal(context.Context, ports.StageFinalRequest) (ports.StageFinalResult, error) {
	return ports.StageFinalResult{}, errors.New("unexpected stage")
}
func (*publicationServiceStore) AdoptStagedFinal(context.Context, ports.AdoptStagedFinalRequest) (ports.StageFinalResult, error) {
	return ports.StageFinalResult{}, errors.New("unexpected staged durability adoption")
}

func (*publicationServiceStore) InstallFinal(context.Context, ports.InstallFinalRequest) (ports.InstallFinalResult, error) {
	return ports.InstallFinalResult{}, errors.New("unexpected install")
}

func (*publicationServiceStore) ReplaceMutable(context.Context, ports.MutableReplaceRequest) (ports.MutableReplaceResult, error) {
	return ports.MutableReplaceResult{}, errors.New("unexpected replacement")
}

func (*publicationServiceStore) CommitPreparedComposite(context.Context, ports.PreparedComposite) (ports.CompositeCommitResult, error) {
	return ports.CompositeCommitResult{}, errors.New("unexpected prepared composite commit")
}

func (*publicationServiceStore) ReadCommittedSnapshot(context.Context, ports.ReadCommittedSnapshotRequest) (ports.CommittedPublicationSnapshot, error) {
	return ports.CommittedPublicationSnapshot{}, errors.New("unexpected snapshot")
}

func (*publicationServiceStore) WriteCorruptionDiagnostic(context.Context, ports.CorruptionDiagnosticRequest) (ports.CorruptionDiagnosticResult, error) {
	return ports.CorruptionDiagnosticResult{}, errors.New("unexpected diagnostic")
}

var _ ports.PublicationStore = (*publicationServiceStore)(nil)

type publicationServiceFailingValidator struct{}

func (publicationServiceFailingValidator) Validate(context.Context, ports.AssetID, []byte) error {
	return errors.New("schema rejected final candidate")
}

type publicationServiceFailAfterPreflightValidator struct {
	calls int
}

func (validator *publicationServiceFailAfterPreflightValidator) Validate(context.Context, ports.AssetID, []byte) error {
	validator.calls++
	if validator.calls > 2 {
		return errors.New("issued publication build rejected")
	}
	return nil
}

type publicationServiceClassifiedFailure struct {
	class domain.FailureClass
}

func (failure publicationServiceClassifiedFailure) Error() string {
	return "classified publication failure"
}

func (failure publicationServiceClassifiedFailure) PublicationFailureClass() domain.FailureClass {
	return failure.class
}

type publicationServiceFixture struct {
	root      ports.AnchoredRoot
	run       ports.PublicationRun
	candidate PreparedCandidate
	issued    ports.IssuedReviewID
	bundle    PublicationBundle
}

func newPublicationServiceFixture(t *testing.T) publicationServiceFixture {
	t.Helper()
	return newPublicationServiceFixtureWithFinding(t, false)
}

func newPublicationServiceFixtureWithFinding(t *testing.T, withFinding bool) publicationServiceFixture {
	t.Helper()

	root, err := ports.NewAnchoredRoot("/tmp/publication-service")
	if err != nil {
		t.Fatal(err)
	}
	candidate := publicationTestCandidate(t, withFinding)
	run, err := ports.NewPublicationRun(root, candidate.SessionID(), candidate.RunID())
	if err != nil {
		t.Fatal(err)
	}
	reviewID, err := domain.ParseReviewID("019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := ports.NewIssuedReviewID(reviewID, candidate.ValidatedCandidateSHA256())
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := candidate.Build(context.Background(), publicationServiceValidator{}, reviewID, publicationTestTime(), 1)
	if err != nil {
		t.Fatal(err)
	}
	return publicationServiceFixture{
		root: root, run: run, candidate: candidate, issued: issued, bundle: bundle,
	}
}
func newPublicationServiceRuntimeFixture(t *testing.T) publicationServiceFixture {
	t.Helper()

	fixture := newPublicationServiceFixture(t)
	fixture.candidate = publicationRuntimeCandidate(t)
	issued, err := ports.NewIssuedReviewID(fixture.issued.ReviewID(), fixture.candidate.ValidatedCandidateSHA256())
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := fixture.candidate.Build(
		context.Background(),
		publicationServiceValidator{},
		issued.ReviewID(),
		publicationTestTime(),
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.issued = issued
	fixture.bundle = bundle
	return fixture
}

type publicationServiceScriptedStore struct {
	calls              []string
	issueRequests      []ports.IssueReviewIDRequest
	candidateRequests  []ports.PersistValidatedCandidateRequest
	prepareRequests    []ports.PrepareCompositeRequest
	replacements       []ports.MutableReplaceRequest
	diagnosticRequests []ports.CorruptionDiagnosticRequest
	stageBytes         [][]byte

	issue            func(ports.IssueReviewIDRequest) (ports.IssuedReviewID, error)
	observe          func() (ports.PublicationObservation, error)
	persistCandidate func(ports.PersistValidatedCandidateRequest) (ports.PersistValidatedCandidateResult, error)
	persistAuxiliary func(ports.PersistAuxiliaryArtifactRequest) (ports.PersistAuxiliaryArtifactResult, error)
	readAuxiliary    func(ports.ReadAuxiliaryArtifactRequest) (ports.ImmutablePublicationArtifact, error)
	prepare          func(ports.PrepareCompositeRequest) (ports.PreparedComposite, error)
	stage            func(ports.StageFinalRequest) (ports.StageFinalResult, error)
	adopt            func(ports.AdoptStagedFinalRequest) (ports.StageFinalResult, error)
	install          func(ports.InstallFinalRequest) (ports.InstallFinalResult, error)
	replace          func(ports.MutableReplaceRequest) (ports.MutableReplaceResult, error)
	commit           func(ports.PreparedComposite) (ports.CompositeCommitResult, error)
	snapshot         func() (ports.CommittedPublicationSnapshot, error)
	diagnostic       func(ports.CorruptionDiagnosticRequest) (ports.CorruptionDiagnosticResult, error)
	withNextEpoch    func(context.Context, ports.AnchoredRoot, func(context.Context, uint64) error) error
}

type publicationLifecycleRecorder struct {
	events []LifecycleEvent
	failOn LifecycleEvent
}

func (recorder *publicationLifecycleRecorder) ObservePublicationLifecycle(_ context.Context, event LifecycleEvent) error {
	recorder.events = append(recorder.events, event)
	if event == recorder.failOn {
		return errors.New("diagnostic persistence unavailable")
	}
	return nil
}

func (recorder *publicationLifecycleRecorder) requireEvents(t *testing.T, want ...LifecycleEvent) {
	t.Helper()
	if len(recorder.events) != len(want) {
		t.Fatalf("lifecycle events = %#v, want %#v", recorder.events, want)
	}
	for index := range want {
		if recorder.events[index] != want[index] {
			t.Fatalf("lifecycle event %d = %q, want %q", index, recorder.events[index], want[index])
		}
	}
}

func (store *publicationServiceScriptedStore) WithNextPublicationEpoch(
	ctx context.Context,
	root ports.AnchoredRoot,
	publish func(context.Context, uint64) error,
) error {
	store.calls = append(store.calls, "next_epoch")
	if store.withNextEpoch == nil {
		return errors.New("unexpected next epoch transaction")
	}
	return store.withNextEpoch(ctx, root, publish)
}
func (store *publicationServiceScriptedStore) IssueReviewID(_ context.Context, request ports.IssueReviewIDRequest) (ports.IssuedReviewID, error) {
	store.calls = append(store.calls, "issue")
	store.issueRequests = append(store.issueRequests, request)
	if store.issue == nil {
		return ports.IssuedReviewID{}, errors.New("unexpected issue")
	}
	return store.issue(request)
}

func (store *publicationServiceScriptedStore) ResolveRun(context.Context, ports.ResolvePublicationRunRequest) (ports.PublicationRun, error) {
	store.calls = append(store.calls, "resolve")
	return ports.PublicationRun{}, errors.New("unexpected resolve")
}

func (store *publicationServiceScriptedStore) ObserveRun(_ context.Context, _ ports.ObserveRunRequest) (ports.PublicationObservation, error) {
	store.calls = append(store.calls, "observe")
	if store.observe == nil {
		return ports.PublicationObservation{}, errors.New("unexpected observe")
	}
	return store.observe()
}

func (store *publicationServiceScriptedStore) PersistValidatedCandidate(_ context.Context, request ports.PersistValidatedCandidateRequest) (ports.PersistValidatedCandidateResult, error) {
	store.calls = append(store.calls, "candidate")
	store.candidateRequests = append(store.candidateRequests, request)
	if store.persistCandidate == nil {
		return ports.PersistValidatedCandidateResult{}, errors.New("unexpected candidate persistence")
	}
	return store.persistCandidate(request)
}

func (store *publicationServiceScriptedStore) PersistAuxiliaryArtifact(_ context.Context, request ports.PersistAuxiliaryArtifactRequest) (ports.PersistAuxiliaryArtifactResult, error) {
	store.calls = append(store.calls, "auxiliary")
	if store.persistAuxiliary == nil {
		return ports.PersistAuxiliaryArtifactResult{}, errors.New("unexpected auxiliary persistence")
	}
	return store.persistAuxiliary(request)
}

func (store *publicationServiceScriptedStore) ReadAuxiliaryArtifact(_ context.Context, request ports.ReadAuxiliaryArtifactRequest) (ports.ImmutablePublicationArtifact, error) {
	store.calls = append(store.calls, "read_auxiliary")
	if store.readAuxiliary == nil {
		return ports.ImmutablePublicationArtifact{}, errors.New("unexpected auxiliary read")
	}
	return store.readAuxiliary(request)
}

func (store *publicationServiceScriptedStore) PrepareComposite(_ context.Context, request ports.PrepareCompositeRequest) (ports.PreparedComposite, error) {
	store.calls = append(store.calls, "prepare")
	store.prepareRequests = append(store.prepareRequests, request)
	if store.prepare == nil {
		return ports.PreparedComposite{}, errors.New("unexpected preparation")
	}
	return store.prepare(request)
}

func (store *publicationServiceScriptedStore) StageFinal(_ context.Context, request ports.StageFinalRequest) (ports.StageFinalResult, error) {
	store.calls = append(store.calls, "stage")
	bytes, err := io.ReadAll(request.Source())
	if err != nil {
		return ports.StageFinalResult{}, err
	}
	store.stageBytes = append(store.stageBytes, bytes)
	if store.stage == nil {
		return ports.StageFinalResult{}, errors.New("unexpected stage")
	}
	return store.stage(request)
}

func (store *publicationServiceScriptedStore) AdoptStagedFinal(
	_ context.Context,
	request ports.AdoptStagedFinalRequest,
) (ports.StageFinalResult, error) {
	store.calls = append(store.calls, "adopt")
	if store.adopt == nil {
		return ports.StageFinalResult{}, errors.New("unexpected staged durability adoption")
	}
	return store.adopt(request)
}

func (store *publicationServiceScriptedStore) InstallFinal(_ context.Context, request ports.InstallFinalRequest) (ports.InstallFinalResult, error) {
	store.calls = append(store.calls, "install")
	if store.install == nil {
		return ports.InstallFinalResult{}, errors.New("unexpected install")
	}
	return store.install(request)
}

func (store *publicationServiceScriptedStore) ReplaceMutable(_ context.Context, request ports.MutableReplaceRequest) (ports.MutableReplaceResult, error) {
	if request.Document() == ports.MutablePublicationJournal {
		store.calls = append(store.calls, "journal")
	} else {
		store.calls = append(store.calls, "status")
	}
	store.replacements = append(store.replacements, request)
	if store.replace == nil {
		return ports.MutableReplaceResult{}, errors.New("unexpected replacement")
	}
	return store.replace(request)
}

func (store *publicationServiceScriptedStore) CommitPreparedComposite(_ context.Context, prepared ports.PreparedComposite) (ports.CompositeCommitResult, error) {
	store.calls = append(store.calls, "commit")
	if store.commit == nil {
		return ports.CompositeCommitResult{}, errors.New("unexpected prepared composite commit")
	}
	return store.commit(prepared)
}

func (store *publicationServiceScriptedStore) ReadCommittedSnapshot(context.Context, ports.ReadCommittedSnapshotRequest) (ports.CommittedPublicationSnapshot, error) {
	store.calls = append(store.calls, "snapshot")
	if store.snapshot == nil {
		return ports.CommittedPublicationSnapshot{}, errors.New("unexpected snapshot")
	}
	return store.snapshot()
}

func (store *publicationServiceScriptedStore) WriteCorruptionDiagnostic(_ context.Context, request ports.CorruptionDiagnosticRequest) (ports.CorruptionDiagnosticResult, error) {
	store.calls = append(store.calls, "diagnostic")
	store.diagnosticRequests = append(store.diagnosticRequests, request)
	if store.diagnostic == nil {
		return ports.CorruptionDiagnosticResult{}, errors.New("unexpected diagnostic")
	}
	return store.diagnostic(request)
}

var _ ports.PublicationStore = (*publicationServiceScriptedStore)(nil)

func newPublicationServiceHappyStore(t *testing.T, fixture publicationServiceFixture) *publicationServiceScriptedStore {
	t.Helper()

	store := &publicationServiceScriptedStore{}
	store.issue = func(request ports.IssueReviewIDRequest) (ports.IssuedReviewID, error) {
		if request.Run() != fixture.run || request.ValidatedCandidateSHA256() != fixture.candidate.ValidatedCandidateSHA256() {
			return ports.IssuedReviewID{}, errors.New("unexpected issuance binding")
		}
		return fixture.issued, nil
	}
	store.persistCandidate = func(request ports.PersistValidatedCandidateRequest) (ports.PersistValidatedCandidateResult, error) {
		if !sameFinalArtifact(request.Candidate(), fixture.bundle.Final()) {
			return ports.PersistValidatedCandidateResult{}, errors.New("candidate bytes differ from issued final")
		}
		receipt := publicationServiceReceipt(t, fixture.root, request.Path(), request.Candidate().Identity().SHA256(), len(request.Candidate().Bytes()))
		return ports.NewPersistValidatedCandidateResult(request.Candidate(), request.Path(), receipt, ports.ValidatedCandidateDurable)
	}
	store.persistAuxiliary = func(request ports.PersistAuxiliaryArtifactRequest) (ports.PersistAuxiliaryArtifactResult, error) {
		artifact := request.Artifact()
		matched := false
		for _, expected := range fixture.bundle.Excerpts() {
			if sameImmutableArtifact(artifact, expected) {
				matched = true
				break
			}
		}
		if !matched {
			return ports.PersistAuxiliaryArtifactResult{}, errors.New("auxiliary artifact differs from deterministic bundle")
		}
		receipt := publicationServiceReceipt(
			t,
			fixture.root,
			artifact.Path(),
			artifact.SHA256(),
			len(artifact.Bytes()),
		)
		return ports.NewPersistAuxiliaryArtifactResult(
			artifact,
			receipt,
			ports.AuxiliaryArtifactDurable,
		)
	}
	store.readAuxiliary = func(request ports.ReadAuxiliaryArtifactRequest) (ports.ImmutablePublicationArtifact, error) {
		expectedSHA256, hasExpectedSHA256 := request.ExpectedSHA256()
		for _, expected := range fixture.bundle.SupportArtifacts() {
			if request.Path() == expected.Path() && (!hasExpectedSHA256 || expectedSHA256 == expected.SHA256()) {
				return expected, nil
			}
		}
		return ports.ImmutablePublicationArtifact{}, errors.New("run support artifact is absent")
	}
	store.prepare = func(request ports.PrepareCompositeRequest) (ports.PreparedComposite, error) {
		return publicationServicePreparedCompositeForRequest(t, fixture.root, request), nil
	}
	store.stage = func(request ports.StageFinalRequest) (ports.StageFinalResult, error) {
		expectedLength, lengthPresent := request.ExpectedByteLength()
		if request.IssuedReviewID() != fixture.issued ||
			request.Final() != fixture.bundle.Final().Identity() ||
			request.StagedPath() != fixture.bundle.StagedFinal().Path() ||
			!lengthPresent || expectedLength != int64(len(fixture.bundle.Final().Bytes())) ||
			!bytes.Equal(store.stageBytes[len(store.stageBytes)-1], fixture.bundle.Final().Bytes()) {
			return ports.StageFinalResult{}, errors.New("staged source differs from deterministic bundle")
		}
		receipt := publicationServiceReceipt(t, fixture.root, request.StagedPath(), request.Final().SHA256(), len(fixture.bundle.Final().Bytes()))
		return ports.NewStageFinalResult(request.StagedPath(), request.Final(), receipt, ports.StageFinalDurable)
	}
	store.adopt = func(request ports.AdoptStagedFinalRequest) (ports.StageFinalResult, error) {
		if request.IssuedReviewID() != fixture.issued ||
			!sameFinalArtifact(request.Final(), fixture.bundle.Final()) {
			return ports.StageFinalResult{}, errors.New("adopted staged final differs from durable candidate")
		}
		receipt := publicationServiceReceipt(
			t,
			fixture.root,
			request.StagedPath(),
			request.Final().Identity().SHA256(),
			len(request.Final().Bytes()),
		)
		return ports.NewStageFinalResult(
			request.StagedPath(),
			request.Final().Identity(),
			receipt,
			ports.StageFinalDurable,
		)
	}
	store.install = func(request ports.InstallFinalRequest) (ports.InstallFinalResult, error) {
		staged := request.Staged()
		receipt := publicationServiceReceipt(t, fixture.root, staged.Final().Path(), staged.Final().SHA256(), len(fixture.bundle.Final().Bytes()))
		return ports.NewInstallFinalResult(staged.Final(), receipt, ports.InstallFinalDurable)
	}
	store.replace = func(request ports.MutableReplaceRequest) (ports.MutableReplaceResult, error) {
		receipt := publicationServiceReceipt(t, fixture.root, request.Path(), request.SHA256(), len(request.Replacement()))
		return ports.NewMutableReplaceResult(request, receipt, ports.MutableReplaceDurable)
	}
	store.commit = func(prepared ports.PreparedComposite) (ports.CompositeCommitResult, error) {
		return publicationServiceCommittedComposite(t, fixture.root, prepared), nil
	}
	snapshot, err := ports.NewCommittedPublicationSnapshot(
		fixture.bundle.Final(),
		fixture.bundle.Manifest(),
		fixture.bundle.LineageEdge(),
		fixture.bundle.Epoch(),
	)
	if err != nil {
		t.Fatal(err)
	}
	normalExit, err := validateCommittedSnapshotSemantics(fixture.run, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	completedJournal := publicationServiceJournalForState(t, fixture.bundle.Journal(), domain.JournalCompleted)
	material := publicationServiceP2RecoveryMaterial(t, fixture.bundle, completedJournal)
	store.observe = func() (ports.PublicationObservation, error) {
		return publicationServiceP2Observation(
			t,
			domain.JournalCompleted,
			normalExit,
			fixture.bundle.Epoch().Value(),
			material,
		), nil
	}
	store.snapshot = func() (ports.CommittedPublicationSnapshot, error) {
		return snapshot, nil
	}
	return store
}

func publicationServicePreparedComposite(
	t *testing.T,
	root ports.AnchoredRoot,
	run ports.PublicationRun,
	bundle PublicationBundle,
) ports.PreparedComposite {
	t.Helper()

	composite, err := ports.NewCommitCompositeRequest(run, bundle.Final().Identity(), bundle.Manifest(), bundle.LineageEdge(), bundle.Epoch())
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewPrepareCompositeRequest(composite)
	if err != nil {
		t.Fatal(err)
	}
	return publicationServicePreparedCompositeForRequest(t, root, request)
}

func publicationServicePreparedCompositeForRequest(
	t *testing.T,
	root ports.AnchoredRoot,
	request ports.PrepareCompositeRequest,
) ports.PreparedComposite {
	t.Helper()

	composite := request.Composite()
	manifest, err := ports.NewImmutablePublicationArtifact(request.StagedManifestPath(), composite.Manifest().SHA256(), composite.Manifest().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	lineage, err := ports.NewImmutablePublicationArtifact(request.StagedLineageEdgePath(), composite.LineageEdge().SHA256(), composite.LineageEdge().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := ports.NewImmutablePublicationArtifact(request.StagedEpochPath(), composite.Epoch().Record().SHA256(), composite.Epoch().Record().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	receipts := []ports.SecureWriteReceipt{
		publicationServiceReceipt(t, root, manifest.Path(), manifest.SHA256(), len(manifest.Bytes())),
		publicationServiceReceipt(t, root, lineage.Path(), lineage.SHA256(), len(lineage.Bytes())),
		publicationServiceReceipt(t, root, epoch.Path(), epoch.SHA256(), len(epoch.Bytes())),
	}
	prepared, err := ports.NewPreparedComposite(
		request,
		manifest,
		lineage,
		epoch,
		receipts,
		ports.CompositePreparationDurable,
	)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func publicationServiceCommittedComposite(
	t *testing.T,
	root ports.AnchoredRoot,
	prepared ports.PreparedComposite,
) ports.CompositeCommitResult {
	t.Helper()

	composite := prepared.Composite()
	receipts := []ports.SecureWriteReceipt{
		publicationServiceReceipt(t, root, composite.Manifest().Path(), composite.Manifest().SHA256(), len(composite.Manifest().Bytes())),
		publicationServiceReceipt(t, root, composite.LineageEdge().Path(), composite.LineageEdge().SHA256(), len(composite.LineageEdge().Bytes())),
		publicationServiceReceipt(t, root, composite.Epoch().Record().Path(), composite.Epoch().Record().SHA256(), len(composite.Epoch().Record().Bytes())),
	}
	result, err := ports.NewCompositeCommitResult(ports.CompositeCommittedDurable, receipts)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func publicationServiceRecoveryMaterial(
	t *testing.T,
	bundle PublicationBundle,
	journal PublicationDocument,
	stagedPath *ports.SafeRelativePath,
	prepared ports.PreparedComposite,
) ports.PublicationRecoveryMaterial {
	t.Helper()

	observed, err := ports.NewObservedMutablePublicationDocument(
		ports.MutablePublicationJournal,
		journal.Path(),
		journal.SHA256(),
		journal.Bytes(),
	)
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewPublicationRecoveryMaterialWithPrepared(
		bundle.Final(),
		stagedPath,
		observed,
		nil,
		bundle.Final(),
		prepared,
	)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func publicationServiceP2RecoveryMaterial(
	t *testing.T,
	bundle PublicationBundle,
	journal PublicationDocument,
) ports.PublicationRecoveryMaterial {
	t.Helper()
	observedJournal, err := ports.NewObservedMutablePublicationDocument(
		ports.MutablePublicationJournal,
		journal.Path(),
		journal.SHA256(),
		journal.Bytes(),
	)
	if err != nil {
		t.Fatal(err)
	}
	status := bundle.Status()
	observedStatus, err := ports.NewObservedMutablePublicationDocument(
		ports.MutablePublicationStatus,
		status.Path(),
		status.SHA256(),
		status.Bytes(),
	)
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewPublicationRecoveryMaterialWithCommittedSnapshot(
		bundle.Final(),
		observedJournal,
		observedStatus,
		publicationServiceSnapshot(t, bundle),
	)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func publicationServiceSnapshot(t *testing.T, bundle PublicationBundle) ports.CommittedPublicationSnapshot {
	t.Helper()
	snapshot, err := ports.NewCommittedPublicationSnapshot(
		bundle.Final(),
		bundle.Manifest(),
		bundle.LineageEdge(),
		bundle.Epoch(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func publicationServiceP2Observation(
	t *testing.T,
	state domain.PersistedJournalState,
	normalExit domain.OperationalExitCode,
	epoch uint64,
	material ports.PublicationRecoveryMaterial,
) ports.PublicationObservation {
	t.Helper()
	observation, err := ports.NewPublicationObservationWithRecovery(
		state,
		domain.DurableObservationP2Committed,
		&normalExit,
		nil,
		epoch,
		material,
	)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func publicationServiceObservationWithMaterial(
	t *testing.T,
	state domain.PersistedJournalState,
	observation domain.DurableObservationClass,
	epoch uint64,
	material ports.PublicationRecoveryMaterial,
) ports.PublicationObservation {
	t.Helper()

	value, err := ports.NewPublicationObservationWithRecovery(state, observation, nil, nil, epoch, material)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func publicationServiceObservation(
	t *testing.T,
	state domain.PersistedJournalState,
	observation domain.DurableObservationClass,
	normalExit *domain.OperationalExitCode,
	reasons []string,
	epoch uint64,
) ports.PublicationObservation {
	t.Helper()

	value, err := ports.NewPublicationObservation(state, observation, normalExit, reasons, epoch)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func publicationServiceJournalForState(
	t *testing.T,
	document PublicationDocument,
	state domain.PersistedJournalState,
) PublicationDocument {
	t.Helper()

	journal, err := journalForState(document, state)
	if err != nil {
		t.Fatal(err)
	}
	return journal
}
func publicationServiceJournalWithCandidateHash(
	t *testing.T,
	document PublicationDocument,
	candidateHash string,
) PublicationDocument {
	t.Helper()

	var wire publicationJournalWire
	if err := json.Unmarshal(document.Bytes(), &wire); err != nil {
		t.Fatal(err)
	}
	wire.ValidatedCandidateSHA256 = candidateHash
	bytes, err := marshalCanonical(wire)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := mutableDocument(document.Path(), bytes)
	if err != nil {
		t.Fatal(err)
	}
	return updated
}

func publicationServiceReceipt(
	t *testing.T,
	root ports.AnchoredRoot,
	path ports.SafeRelativePath,
	sha256 string,
	length int,
) ports.SecureWriteReceipt {
	t.Helper()

	receipt, err := ports.NewSecureWriteReceipt(root, path, sha256, int64(length), "test", []string{"test"})
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func publicationServiceCallsEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func publicationServiceAssertJournalCAS(t *testing.T, replacements []ports.MutableReplaceRequest) {
	t.Helper()

	if len(replacements) != 6 {
		t.Fatalf("mutable replacements = %d, want 6", len(replacements))
	}
	wantDocuments := []ports.MutablePublicationDocument{
		ports.MutablePublicationJournal,
		ports.MutablePublicationJournal,
		ports.MutablePublicationJournal,
		ports.MutablePublicationJournal,
		ports.MutablePublicationStatus,
		ports.MutablePublicationJournal,
	}
	for index, document := range wantDocuments {
		if replacements[index].Document() != document {
			t.Fatalf("replacement %d document = %q, want %q", index, replacements[index].Document(), document)
		}
	}
	if !replacements[0].ExpectedPrior().MustBeAbsent() || !replacements[4].ExpectedPrior().MustBeAbsent() {
		t.Fatal("initial journal and status replacements must require absence")
	}
	for _, edge := range [][2]int{{0, 1}, {1, 2}, {2, 3}, {3, 5}} {
		expected, ok := replacements[edge[1]].ExpectedPrior().ExpectedSHA256()
		if !ok || expected != replacements[edge[0]].SHA256() {
			t.Fatalf("replacement %d CAS = (%q, %t), want journal %d SHA %q", edge[1], expected, ok, edge[0], replacements[edge[0]].SHA256())
		}
	}
}

func publicationServiceRequireFailureClass(t *testing.T, err error, want domain.FailureClass) {
	t.Helper()

	var failure *domain.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("error %v is not a typed publication failure", err)
	}
	if failure.Class() != want {
		t.Fatalf("failure class = %q, want %q", failure.Class(), want)
	}
}

func TestTerminalManifestFailureReasonsIgnoreRecoveredHistoricalAttemptsAndFollowRoleOrder(t *testing.T) {
	recovered := "a_recovered"
	logicFallback := "a_logic_fallback"
	securityTerminal := "a_security_terminal"
	manifest := runManifestWire{
		SelectedRoles: []string{"logic", "security"},
		Attempts: []manifestAttemptWire{
			{AttemptID: recovered, Role: "logic", State: string(domain.AttemptTimedOut)},
			{AttemptID: logicFallback, Role: "logic", State: string(domain.AttemptFailed)},
			{AttemptID: securityTerminal, Role: "security", State: string(domain.AttemptFailed)},
		},
		Failures: []manifestFailureWire{
			{ReasonCode: "provider_permission_denied", AttemptID: &securityTerminal},
			{ReasonCode: "provider_timeout", AttemptID: &recovered},
			{ReasonCode: "provider_output_missing", AttemptID: &logicFallback},
		},
	}
	reasons := terminalManifestFailureReasons(manifest)
	want := []string{"provider_output_missing", "provider_permission_denied"}
	if !reflect.DeepEqual(reasons, want) {
		t.Fatalf("terminal reasons = %#v, want %#v", reasons, want)
	}
}
