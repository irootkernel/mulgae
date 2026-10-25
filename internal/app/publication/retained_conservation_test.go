package publication

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestRetainedLiveP2ExitRetainsAllTerminalRoleAndPolicyReasons(t *testing.T) {
	t.Parallel()

	candidate := retainedLiveCandidate(t, true)
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
		role.reportsOnly = false
		role.reportMarkdown = nil
		role.outputTransport = ""
		role.attempts[0].state = domain.AttemptFailed
		role.attempts[0].parseState = domain.ParseNotStarted
		role.attempts[0].validationState = domain.ValidationNotStarted
		role.attempts[0].invocations[0].state = domain.InvocationFailed
		attemptID := role.attempts[0].id
		candidate.failures = append(candidate.failures, preparedFailure{
			class: failure.class, stage: "review", reason: failure.reason, attemptID: &attemptID,
		})
	}
	candidate.runState = domain.RunFailed
	candidate.axes = preparedAxes{
		content: domain.ContentRequestChanges, coverage: domain.CoverageIncomplete, ci: domain.CIFail,
		structuredExtraction: domain.StructuredExtractionStructured,
	}
	candidate.reasons = []string{"request_changes_threshold", "required_role_incomplete"}
	candidate.exitCode = int(domain.ExitIncompleteCoverage)
	candidate.limits = []string{"Required review coverage is incomplete."}
	agyArtist := candidate.target.live.provenance.Providers[0]
	agyArtist.Instance = "agy-artist"
	candidate.target.live.provenance.Providers = []ProductionProviderProvenance{
		agyArtist,
		candidate.target.live.provenance.Providers[0],
		candidate.target.live.provenance.Providers[1],
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
	bundle, err := candidate.Build(context.Background(), retainedSchema(t), reviewID, publicationTestTime(), 1)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := ports.NewIssuedReviewID(reviewID, candidate.ValidatedCandidateSHA256())
	if err != nil {
		t.Fatal(err)
	}
	fixture := publicationServiceFixture{root: root, run: run, candidate: candidate, issued: issued, bundle: bundle}
	store := newPublicationServiceHappyStore(t, fixture)
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	result, err := publishRetainedLive(t, service, context.Background(), fixture)
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
func TestRetainedLiveObservedClassifiesPreflightFailure(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	store.withNextEpoch = func(ctx context.Context, root ports.AnchoredRoot, publish func(context.Context, uint64) error) error {
		return publish(ctx, fixture.bundle.Epoch().Value())
	}
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, 1)
	if err != nil {
		t.Fatal(err)
	}
	observer := &publicationLifecycleRecorder{}

	if _, err := publishRetainedLive(t, service, context.Background(), fixture, observer); err == nil {
		t.Fatal("PublishNextObserved succeeded with an undersized publication limit")
	}
	observer.requireEvents(t, LifecyclePreparationStarted, LifecycleFailed)
	if len(observer.diagnostics) != 1 {
		t.Fatalf("failure diagnostics = %#v, want one", observer.diagnostics)
	}
	diagnostic := observer.diagnostics[0]
	if diagnostic.Phase() != domain.DiagnosticPhasePublicationFinalReview ||
		diagnostic.Cause() != domain.DiagnosticCausePublicationSerializationFailed {
		t.Fatalf("failure diagnostic = (%q, %q), want final_review/serialization", diagnostic.Phase(), diagnostic.Cause())
	}
}

func TestRetainedLiveNextRejectsStoreWithoutAtomicEpochTransaction(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
	store := &publicationServiceStore{}
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.PublishLiveNext(context.Background(), fixture.root, PreparedLiveCandidate{candidate: fixture.candidate})
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureConfiguration || failure.Reason() != "publication store does not support atomic epoch commits" || store.issueCalls != 0 {
		t.Fatalf("atomic capability guard: %v; issue calls=%d", err, store.issueCalls)
	}
}

func TestRetainedLiveCompletedJournalWithoutPromptsKeepsAllSupport(t *testing.T) {
	fixture := retainedLiveServiceFixture(t)
	attempt := fixture.candidate.roles[0].attempts[0].id
	store := newPublicationServiceHappyStore(t, fixture)
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Recover(context.Background(), fixture.run)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatal("prompt-free recovery lost P2")
	}
	if _, ok := result.PromptManifestArtifact(attempt, 1); ok {
		t.Fatal("completed-journal recovery invented a prompt manifest")
	}
	if got, want := len(result.PersistedRunSupportArtifacts()), len(fixture.bundle.SupportArtifacts()); got != want || want == 0 {
		t.Fatalf("support identities = %d, want complete nonzero %d", got, want)
	}
	if len(store.issueRequests) != 0 {
		t.Fatal("completed recovery issued an identity")
	}
}
