package publication

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func retainedLiveServiceFixture(t *testing.T) publicationServiceFixture {
	t.Helper()
	return retainedLiveFindingServiceFixture(t, false)
}

func retainedLiveFindingServiceFixture(t *testing.T, withFinding bool) publicationServiceFixture {
	t.Helper()
	candidate := retainedLiveCandidate(t, withFinding)
	root, err := ports.NewAnchoredRoot("/private/retained-live-service")
	if err != nil {
		t.Fatal(err)
	}
	run, err := ports.NewPublicationRun(root, candidate.SessionID(), candidate.RunID())
	if err != nil {
		t.Fatal(err)
	}
	issued, err := ports.NewIssuedReviewID(publicationIssuedReviewID(t), candidate.ValidatedCandidateSHA256())
	if err != nil {
		t.Fatal(err)
	}
	live := PreparedLiveCandidate{candidate: candidate}
	if !live.Valid() || candidate.target.live == nil || len(candidate.capturedArchive) != 0 || withFinding && len(candidate.findings) != 1 {
		t.Fatal("live fixture positive admission failed")
	}
	bundle, err := live.Build(context.Background(), retainedSchema(t), issued.ReviewID(), publicationTestTime(), 1)
	if err != nil {
		t.Fatal(err)
	}
	return publicationServiceFixture{root: root, run: run, candidate: candidate, issued: issued, bundle: bundle}
}

// The live entrypoint actually performs its initial observation and unjournaled
// inspection. Only these new-run store inputs are added to the original
// post-effect scripts; their later receipts/observations are left intact.
type retainedLiveServiceStore struct {
	*publicationServiceScriptedStore
	initial bool
}

func (store *retainedLiveServiceStore) ObserveRun(ctx context.Context, request ports.ObserveRunRequest) (ports.PublicationObservation, error) {
	if !store.initial {
		store.initial = true
		store.calls = append(store.calls, "observe_live_start")
		return ports.NewPublicationObservation(domain.JournalCollecting, domain.DurableObservationP0None, nil, nil, 1)
	}
	return store.publicationServiceScriptedStore.ObserveRun(ctx, request)
}

func (store *retainedLiveServiceStore) ReadUnjournaledCompositeCandidate(context.Context, ports.ObserveRunRequest) (ports.FinalReviewArtifact, bool, error) {
	store.calls = append(store.calls, "read_unjournaled")
	return ports.FinalReviewArtifact{}, false, nil
}

func (store *retainedLiveServiceStore) AdoptCompositePreparationArtifact(context.Context, ports.PublicationRun, ports.ImmutablePublicationArtifact) (bool, error) {
	return false, errors.New("new-run script unexpectedly requested adoption")
}

type retainedFailAfterSchema struct {
	base  *retainedRecordingSchema
	calls int
}

func (validator *retainedFailAfterSchema) Validate(ctx context.Context, id ports.AssetID, raw []byte) error {
	if err := validator.base.Validate(ctx, id, raw); err != nil {
		return err
	}
	validator.calls++
	if validator.calls > 2 {
		return errors.New("issued publication build rejected")
	}
	return nil
}

func publishRetainedLive(t *testing.T, service *Service, ctx context.Context, fixture publicationServiceFixture, observers ...LifecycleObserver) (PublicationResult, error) {
	t.Helper()
	store, ok := service.store.(*publicationServiceScriptedStore)
	if !ok {
		t.Fatal("expected original scripted store")
	}
	service.store = &retainedLiveServiceStore{publicationServiceScriptedStore: store}
	if store.withNextEpoch == nil {
		store.withNextEpoch = func(commitCtx context.Context, root ports.AnchoredRoot, publish func(context.Context, uint64) error) error {
			if root != fixture.root {
				t.Fatal("live epoch transaction rebound artifact root")
			}
			return publish(commitCtx, fixture.bundle.Epoch().Value())
		}
	}
	if len(observers) == 1 {
		return service.PublishLiveNextObserved(ctx, fixture.root, PreparedLiveCandidate{candidate: fixture.candidate}, observers[0])
	}
	return service.PublishLiveNext(ctx, fixture.root, PreparedLiveCandidate{candidate: fixture.candidate})
}

func retainedLiveCallsEqual(actual, want []string) bool {
	expected := append([]string{"next_epoch", "observe_live_start", "read_unjournaled"}, want...)
	return publicationServiceCallsEqual(actual, expected)
}

func TestRetainedLivePublishPersistsAndPublishesInDurableOrder(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	result, err := publishRetainedLive(t, service, context.Background(), fixture)
	if err != nil {
		t.Fatal(err)
	}
	if !retainedLiveCallsEqual(store.calls, publicationServiceExpectedPersistCalls(fixture, "prepare", "journal", "stage", "journal", "install",
		"journal", "commit", "journal", "status", "journal", "observe")) {
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

func TestRetainedLivePublishReconcilesValidIssuedIDReturnedWithError(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
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
		retainedSchema(t),
		publicationServiceClock{now: publicationTestTime()},
		publicationServiceTestMaxBytes,
	)
	if err != nil {
		t.Fatal(err)
	}

	result, err := publishRetainedLive(t, service, context.Background(), fixture)
	if err != nil {
		t.Fatal(err)
	}
	if issued, ok := result.IssuedReviewID(); !ok || issued != fixture.issued {
		t.Fatalf("reconciled issued ID = (%#v, %t), want (%#v, true)", issued, ok, fixture.issued)
	}
	if len(store.issueRequests) != 1 || len(store.candidateRequests) != 0 ||
		!retainedLiveCallsEqual(store.calls, publicationServiceObserveReadCalls(fixture, "issue", "observe")) {
		t.Fatalf("ambiguous issuance calls = %#v, issue requests = %d, candidate requests = %d", store.calls, len(store.issueRequests), len(store.candidateRequests))
	}
}

func TestRetainedLivePublishReobservesValidMismatchedIssuedIDWithError(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
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
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	_, err = publishRetainedLive(t, service, context.Background(), fixture)
	publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
	if !retainedLiveCallsEqual(store.calls, []string{"issue", "observe"}) {
		t.Fatalf("mismatched issuance calls = %#v", store.calls)
	}
}

func TestRetainedLivePublishRejectsIssuedCandidateMismatchEvenWhenObservedP2MatchesIssuedID(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
	staleCandidate := retainedLiveCandidate(t, false)
	staleCandidate.mulgae.commit = "stale-build"
	staleCandidate.target.live.provenance.BuildCommit = "stale-build"
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
		retainedSchema(t),
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
		retainedSchema(t),
		publicationServiceClock{now: publicationTestTime()},
		publicationServiceTestMaxBytes,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = publishRetainedLive(t, service, context.Background(), fixture)
	publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
	if len(store.issueRequests) != 1 || len(store.candidateRequests) != 0 ||
		!retainedLiveCallsEqual(store.calls, []string{"issue", "observe"}) {
		t.Fatalf("stale P2 issuance calls = %#v", store.calls)
	}
}

func TestRetainedLivePublishDoesNotReissueAfterReconciledIssuanceBeforeBuildFailure(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
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
	validator := &retainedFailAfterSchema{base: retainedSchema(t)}
	service, err := NewService(store, validator, publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	_, err = publishRetainedLive(t, service, context.Background(), fixture)
	publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
	if len(store.issueRequests) != 1 || !retainedLiveCallsEqual(store.calls, []string{"issue", "observe"}) {
		t.Fatalf("issuance/build failure calls = %#v, issue requests = %d", store.calls, len(store.issueRequests))
	}
}

func TestRetainedLivePublishReobservesValidMismatchedCandidateResultWithError(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
	otherReviewID, err := domain.ParseReviewID("019f596a-d174-7321-b920-c2d312c82cc4")
	if err != nil {
		t.Fatal(err)
	}
	otherBundle, err := fixture.candidate.Build(
		context.Background(),
		retainedSchema(t),
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
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	result, err := publishRetainedLive(t, service, context.Background(), fixture)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision().Authority() != domain.PublicationAuthorityP2 ||
		!retainedLiveCallsEqual(store.calls, publicationServiceObserveReadCalls(fixture, "issue", "candidate", "observe")) {
		t.Fatalf("mismatched candidate reconciliation = (%q, %#v)", result.Decision().Authority(), store.calls)
	}
}

func TestRetainedLivePublishUndurableCandidateReobservesWithoutFurtherPublication(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
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
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	_, err = publishRetainedLive(t, service, context.Background(), fixture)
	publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
	if !retainedLiveCallsEqual(store.calls, []string{"issue", "candidate", "observe"}) {
		t.Fatalf("publication calls after undurable candidate = %#v", store.calls)
	}
}

func TestRetainedLivePublishReobservesEveryValidPostEffectResult(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		inject     func(*publicationServiceScriptedStore)
		wantCalls  []string
		wantSuffix []string
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
			wantSuffix: []string{"prepare", "observe"},
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
			wantSuffix: []string{"prepare", "journal", "observe"},
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
			wantSuffix: []string{"prepare", "journal", "stage", "observe"},
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
			wantSuffix: []string{"prepare", "journal", "stage", "journal", "install", "observe"},
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
			wantSuffix: []string{"prepare", "journal", "stage", "journal", "install", "journal", "commit", "observe"},
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
			wantSuffix: []string{"prepare", "journal", "stage", "journal", "install", "journal", "commit", "journal", "status", "observe"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := retainedLiveServiceFixture(t)
			store := newPublicationServiceHappyStore(t, fixture)
			test.inject(store)
			service, err := NewService(
				store,
				retainedSchema(t),
				publicationServiceClock{now: publicationTestTime()},
				publicationServiceTestMaxBytes,
			)
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
			wantCalls := append([]string(nil), test.wantCalls...)
			if len(test.wantSuffix) != 0 {
				wantCalls = publicationServiceExpectedPersistCalls(fixture, test.wantSuffix...)
			}
			for range fixture.bundle.SupportArtifacts() {
				wantCalls = append(wantCalls, "read_auxiliary")
			}
			if !retainedLiveCallsEqual(store.calls, wantCalls) {
				t.Fatalf("calls = %#v, want %#v", store.calls, wantCalls)
			}
		})
	}
}

func TestRetainedLivePublishReobservesValidAuxiliaryPostEffectResult(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveFindingServiceFixture(t, true)
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
		retainedSchema(t),
		publicationServiceClock{now: publicationTestTime()},
		publicationServiceTestMaxBytes,
	)
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
	want := []string{"issue", "candidate", "auxiliary", "observe"}
	for range fixture.bundle.SupportArtifacts() {
		want = append(want, "read_auxiliary")
	}
	if !retainedLiveCallsEqual(store.calls, want) {
		t.Fatalf("calls = %#v, want %#v", store.calls, want)
	}
}
func TestRetainedLivePublishPreventsP2WhenPersistedRunSupportCannotBeRead(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveFindingServiceFixture(t, true)
	store := newPublicationServiceHappyStore(t, fixture)
	store.readAuxiliary = func(ports.ReadAuxiliaryArtifactRequest) (ports.ImmutablePublicationArtifact, error) {
		return ports.ImmutablePublicationArtifact{}, errors.New("run support artifact is absent")
	}
	service, err := NewService(
		store,
		retainedSchema(t),
		publicationServiceClock{now: publicationTestTime()},
		publicationServiceTestMaxBytes,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := publishRetainedLive(t, service, context.Background(), fixture); err == nil {
		t.Fatal("Publish committed P2 with missing run support")
	}
	if want := []string{"issue", "candidate", "auxiliary", "read_auxiliary"}; !retainedLiveCallsEqual(store.calls, want) {
		t.Fatalf("calls = %#v, want %#v", store.calls, want)
	}
}

func TestRetainedLivePublishRejectsStageAndInstallReceiptLengthMismatches(t *testing.T) {
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
			fixture := retainedLiveServiceFixture(t)
			store := newPublicationServiceHappyStore(t, fixture)
			test.inject(store, fixture)
			service, err := NewService(
				store,
				retainedSchema(t),
				publicationServiceClock{now: publicationTestTime()},
				publicationServiceTestMaxBytes,
			)
			if err != nil {
				t.Fatal(err)
			}

			_, err = publishRetainedLive(t, service, context.Background(), fixture)
			publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
		})
	}
}

func TestRetainedLivePublishStopsAtCancellationBoundaryAfterIDIssuance(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	ctx, cancel := context.WithCancel(context.Background())
	store.issue = func(request ports.IssueReviewIDRequest) (ports.IssuedReviewID, error) {
		cancel()
		return fixture.issued, nil
	}
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	_, err = publishRetainedLive(t, service, ctx, fixture)
	publicationServiceRequireFailureClass(t, err, domain.FailureCancelled)
	if !retainedLiveCallsEqual(store.calls, []string{"issue"}) {
		t.Fatalf("publication calls after cancellation = %#v", store.calls)
	}
}

func TestRetainedLiveObservedReportsDurableLifecycle(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	store.withNextEpoch = func(ctx context.Context, root ports.AnchoredRoot, publish func(context.Context, uint64) error) error {
		return publish(ctx, fixture.bundle.Epoch().Value())
	}
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	observer := &publicationLifecycleRecorder{}

	result, err := publishRetainedLive(t, service, context.Background(), fixture, observer)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatalf("authority = %q, want P2", result.Decision().Authority())
	}
	observer.requireEvents(t, LifecyclePreparationStarted, LifecycleStaged, LifecycleInstalled, LifecycleCommitted)
}

func TestRetainedLiveObservedPersistenceFailureStopsBeforeInstall(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	store.withNextEpoch = func(ctx context.Context, root ports.AnchoredRoot, publish func(context.Context, uint64) error) error {
		return publish(ctx, fixture.bundle.Epoch().Value())
	}
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	observer := &publicationLifecycleRecorder{failOn: LifecycleStaged}

	returned, err := publishRetainedLive(t, service, context.Background(), fixture, observer)
	if err == nil {
		t.Fatal("PublishNextObserved succeeded after lifecycle persistence failure")
	}
	publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
	if diagnostic, ok := FailureDiagnosticFromError(err); ok {
		t.Fatalf("diagnostic persistence failure was misclassified as publication failure: %#v", diagnostic)
	}
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

func TestRetainedLiveObservedClassifiesStoreLockFailure(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	store.withNextEpoch = func(context.Context, ports.AnchoredRoot, func(context.Context, uint64) error) error {
		return errors.New("lock unavailable at /private/store")
	}
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	observer := &publicationLifecycleRecorder{}

	if _, err := publishRetainedLive(t, service, context.Background(), fixture, observer); err == nil {
		t.Fatal("PublishNextObserved succeeded after store lock failure")
	}
	observer.requireEvents(t, LifecycleFailed)
	if len(observer.diagnostics) != 1 {
		t.Fatalf("failure diagnostics = %#v, want one", observer.diagnostics)
	}
	diagnostic := observer.diagnostics[0]
	if diagnostic.Phase() != domain.DiagnosticPhasePublicationStoreLock ||
		diagnostic.Cause() != domain.DiagnosticCausePublicationStoreLockFailed ||
		strings.Contains(diagnostic.Failure(), "/private/store") {
		t.Fatalf("failure diagnostic = %#v, want redacted store-lock classification", diagnostic)
	}
}

func TestRetainedLiveObservedClassifiesInstallationFailure(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	store.withNextEpoch = func(ctx context.Context, root ports.AnchoredRoot, publish func(context.Context, uint64) error) error {
		return publish(ctx, fixture.bundle.Epoch().Value())
	}
	store.install = func(ports.InstallFinalRequest) (ports.InstallFinalResult, error) {
		return ports.InstallFinalResult{}, errors.New("installation failed at /private/store")
	}
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	observer := &publicationLifecycleRecorder{}

	if _, err := publishRetainedLive(t, service, context.Background(), fixture, observer); err == nil {
		t.Fatal("PublishNextObserved succeeded after installation failure")
	}
	observer.requireEvents(t, LifecyclePreparationStarted, LifecycleStaged, LifecycleFailed)
	if len(observer.diagnostics) != 1 {
		t.Fatalf("failure diagnostics = %#v, want one", observer.diagnostics)
	}
	diagnostic := observer.diagnostics[0]
	if diagnostic.Phase() != domain.DiagnosticPhasePublicationInstallation ||
		diagnostic.Cause() != domain.DiagnosticCausePublicationInstallationFailed ||
		strings.Contains(diagnostic.Failure(), "/private/store") {
		t.Fatalf("failure diagnostic = %#v, want redacted installation classification", diagnostic)
	}
}

func TestRetainedLiveObservedCommittedPersistenceFailureRetainsP2Evidence(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	store.withNextEpoch = func(ctx context.Context, root ports.AnchoredRoot, publish func(context.Context, uint64) error) error {
		return publish(ctx, fixture.bundle.Epoch().Value())
	}
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	observer := &publicationLifecycleRecorder{failOn: LifecycleCommitted}

	returned, err := publishRetainedLive(t, service, context.Background(), fixture, observer)
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
