package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestRunSupportContractRejectsArbitraryPathsAndRejectedSecretBytes(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
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

	fixture := retainedLiveServiceFixture(t)
	bytes := []byte("runtime inventory")
	base := fixture.run.SessionID().String() + "/" + fixture.run.RunID().String() + "/"
	attemptID := retainedLiveCandidate(t, false).roles[0].attempts[0].id.String()
	cases := []struct {
		path string
		kind ports.RunSupportArtifactKind
	}{
		{base + "target/target.bytes", ports.RunSupportArtifactTargetBytes},
		{base + "target/target-manifest.json", ports.RunSupportArtifactTargetManifest},
		{base + "prompts/" + attemptID + "/001-initial.stdin", ports.RunSupportArtifactPromptStdin},
		{base + "prompts/" + attemptID + "/001-initial.manifest.json", ports.RunSupportArtifactPromptManifest},
		{base + "prompts/" + attemptID + "/002-retry.stdin", ports.RunSupportArtifactPromptStdin},
		{base + "prompts/" + attemptID + "/002-retry.manifest.json", ports.RunSupportArtifactPromptManifest},
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

func TestPublicationVariableSizedSupportPathsUseCanonicalKindPolicy(t *testing.T) {
	t.Parallel()
	candidate := retainedLiveCandidate(t, false)
	base := candidate.sessionID.String() + "/" + candidate.runID.String() + "/"
	attemptID := candidate.roles[0].attempts[0].id.String()
	for _, test := range []struct {
		path string
		want bool
	}{
		{base + "target/target.bytes", true},
		{base + "target/target-manifest.json", true},
		{base + "target/captured-review.json", true},
		{base + "target/blobs/sha256-" + strings.Repeat("a", 64), true},
		{base + "inputs/artist-brief.md", true},
		{base + "inputs/artist-visual-assets.json", true},
		{base + "prompts/" + attemptID + "/001-initial.stdin", true},
		{base + "attempts/" + attemptID + "/invocations/001-initial/stdout.raw", true},
		{base + "attempts/" + attemptID + "/invocations/001-initial/stderr.raw", true},
		{base + "support/index.json", true},
		{base + "prompts/" + attemptID + "/001-initial.manifest.json", false},
		{base + "role-reports/logic.md", false},
		{base + "excerpts/F001.json", false},
	} {
		path, err := ports.NewSafeRelativePath(test.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := publicationVariableSizedSupportPath(path); got != test.want {
			t.Fatalf("publicationVariableSizedSupportPath(%q) = %t, want %t", test.path, got, test.want)
		}
	}
}
func TestRepairedCandidateAndPatchStdoutHaveDistinctCanonicalArtifacts(t *testing.T) {
	t.Parallel()

	candidate := retainedLiveCandidate(t, false)
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
	if _, err := NewChildPublicationContext(domain.RunTypeFollowup, runID, runID, reviewID, nil, nil, nil); err == nil {
		t.Fatal("followup without finding was accepted")
	}
	if _, err := NewChildPublicationContext(domain.RunTypeDelta, runID, runID, reviewID, nil, &finding, nil); err == nil {
		t.Fatal("delta with finding was accepted")
	}
	if _, err := NewChildPublicationContext(domain.RunTypeRerun, runID, runID, reviewID, nil, nil, nil); err == nil {
		t.Fatal("rerun without replay mode was accepted")
	}
	replay := ReplayModeExact
	if _, err := NewChildPublicationContext(domain.RunTypeRerun, runID, runID, reviewID, nil, nil, &replay); err == nil {
		t.Fatal("rerun without exact source attempt was accepted")
	}
	attempt, err := domain.ParseAttemptID("a_019f596a-d048-79e7-b2b7-59822f012273")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewChildPublicationContext(domain.RunTypeDelta, runID, runID, reviewID, &attempt, nil, nil); err == nil {
		t.Fatal("delta with a rerun source attempt was accepted")
	}
}
func publicationLineageWireEqual(left, right immutableLineageWire) bool {
	return left.LineageEdgePath == right.LineageEdgePath &&
		left.LineageEdgeSHA256 == right.LineageEdgeSHA256 &&
		publicationOptionalStringEqual(left.ParentRunID, right.ParentRunID) &&
		publicationOptionalStringEqual(left.SourceRunID, right.SourceRunID) &&
		publicationOptionalStringEqual(left.SourceReviewID, right.SourceReviewID) &&
		publicationOptionalStringEqual(left.SourceAttemptID, right.SourceAttemptID) &&
		publicationOptionalStringEqual(left.SourceFindingRef, right.SourceFindingRef) &&
		publicationOptionalStringEqual(left.ReplayMode, right.ReplayMode)
}

func publicationOptionalAttemptEqual(value *string, attempt *domain.AttemptID) bool {
	if value == nil || attempt == nil {
		return value == nil && attempt == nil
	}
	return *value == attempt.String()
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
	if _, err := service.PublishLiveNext(context.Background(), root, PreparedLiveCandidate{}); err == nil {
		t.Fatal("Publish accepted an invalid candidate")
	}
	if store.issueCalls != 0 {
		t.Fatalf("IssueReviewID calls = %d, want 0", store.issueCalls)
	}
}

func TestPublishRejectsPreflightSchemaFailureBeforeIDIssuance(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	service, err := NewService(
		store,
		publicationServiceFailingValidator{},
		publicationServiceClock{now: publicationTestTime()},
		publicationServiceTestMaxBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publishRetainedLive(t, service, context.Background(), fixture); err == nil {
		t.Fatal("Publish accepted a candidate whose preflight schema validation failed")
	}
	if len(store.issueRequests) != 0 {
		t.Fatalf("IssueReviewID calls = %d, want 0", len(store.issueRequests))
	}
}

func TestPublishRejectsOversizePreflightBeforeIDIssuance(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
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

	store := newPublicationServiceHappyStore(t, fixture)
	service, err := NewService(
		store,
		publicationServiceValidator{},
		publicationServiceClock{now: publicationTestTime()},
		int64(maximum-1),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publishRetainedLive(t, service, context.Background(), fixture); err == nil {
		t.Fatal("Publish accepted a preflight member above the configured cap")
	}
	if len(store.issueRequests) != 0 {
		t.Fatalf("IssueReviewID calls = %d, want 0", len(store.issueRequests))
	}
}

func TestPublishNextUsesRootBoundEpochTransaction(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
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

	result, err := publishRetainedLive(t, service, context.Background(), fixture)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatalf("authority = %q, want P2", result.Decision().Authority())
	}
	want := append([]string{"next_epoch", "observe_live_start", "read_unjournaled"}, publicationServiceExpectedPersistCalls(fixture, "prepare", "journal", "stage", "journal", "install",
		"journal", "commit", "journal", "status", "journal", "observe")...)
	if !publicationServiceCallsEqual(store.calls, want) {
		t.Fatalf("publication calls = %#v", store.calls)
	}
}

func TestPublicationFailureFromCausePreservesCanonicalPrecedence(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		cause error
		want  domain.FailureClass
	}{
		{name: "pure cancellation", cause: context.Canceled, want: domain.FailureCancelled},
		{name: "pure deadline", cause: context.DeadlineExceeded, want: domain.FailureCancelled},
		{name: "artifact over cancellation", cause: errors.Join(context.Canceled, publicationTestFailure(t, domain.FailureArtifact)), want: domain.FailureArtifact},
		{name: "security over cancellation", cause: errors.Join(context.Canceled, publicationTestFailure(t, domain.FailureSecurityPolicy)), want: domain.FailureSecurityPolicy},
		{name: "internal over cancellation", cause: errors.Join(context.Canceled, publicationTestFailure(t, domain.FailureInternal)), want: domain.FailureInternal},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := publicationFailureFromCause(
				context.Background(),
				"publish-next.lock",
				domain.FailureArtifact,
				"publication store lock failed",
				test.cause,
			)
			var failure *domain.Failure
			if !errors.As(err, &failure) || failure.Class() != test.want {
				t.Fatalf("failure = %#v, want class %q", failure, test.want)
			}
			if diagnostic, ok := FailureDiagnosticFromError(err); !ok ||
				diagnostic.Phase() != domain.DiagnosticPhasePublicationStoreLock ||
				diagnostic.Cause() != domain.DiagnosticCausePublicationStoreLockFailed {
				t.Fatalf("diagnostic = %#v, %t, want store-lock diagnostic", diagnostic, ok)
			}
		})
	}
}

func publicationTestFailure(t *testing.T, class domain.FailureClass) error {
	t.Helper()
	failure, err := domain.NewFailure("publication.test", class, "injected failure", nil)
	if err != nil {
		t.Fatal(err)
	}
	return failure
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
	events      []LifecycleEvent
	failOn      LifecycleEvent
	diagnostics []FailureDiagnostic
}

func (recorder *publicationLifecycleRecorder) ObservePublicationLifecycle(_ context.Context, observation LifecycleObservation) error {
	event := observation.Event()
	recorder.events = append(recorder.events, event)
	if diagnostic, ok := observation.FailureDiagnostic(); ok {
		recorder.diagnostics = append(recorder.diagnostics, diagnostic)
	}
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

// publicationServiceExpectedPersistCalls builds the durable publish call prefix
// for a fixture: issue, candidate, then one auxiliary/read pair per support
// artifact, then any caller-owned suffix.
func publicationServiceExpectedPersistCalls(fixture publicationServiceFixture, suffix ...string) []string {
	calls := []string{"issue", "candidate"}
	for range fixture.bundle.SupportArtifacts() {
		calls = append(calls, "auxiliary", "read_auxiliary")
	}
	return append(calls, suffix...)
}

// publicationServiceObserveReadCalls appends one read_auxiliary call per support
// artifact after a recovery observe sequence.
func publicationServiceObserveReadCalls(fixture publicationServiceFixture, prefix ...string) []string {
	calls := append([]string(nil), prefix...)
	for range fixture.bundle.SupportArtifacts() {
		calls = append(calls, "read_auxiliary")
	}
	return calls
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
