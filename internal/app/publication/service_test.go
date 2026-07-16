package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

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
		"issue", "candidate", "prepare", "journal", "stage", "journal", "install",
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
		!publicationServiceCallsEqual(store.calls, []string{"issue", "observe"}) {
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
		!publicationServiceCallsEqual(store.calls, []string{"issue", "candidate", "observe"}) {
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
			wantCalls: []string{"issue", "candidate", "prepare", "observe"},
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
			wantCalls: []string{"issue", "candidate", "prepare", "journal", "observe"},
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
			wantCalls: []string{"issue", "candidate", "prepare", "journal", "stage", "observe"},
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
				"issue", "candidate", "prepare", "journal", "stage", "journal",
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
				"issue", "candidate", "prepare", "journal", "stage", "journal",
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
				"issue", "candidate", "prepare", "journal", "stage", "journal",
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
			if !publicationServiceCallsEqual(store.calls, test.wantCalls) {
				t.Fatalf("calls = %#v, want %#v", store.calls, test.wantCalls)
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
	if want := []string{"issue", "candidate", "auxiliary", "observe"}; !publicationServiceCallsEqual(store.calls, want) {
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

	_, err = service.p2Result(context.Background(), fixture.run, &mismatchedIssued, nil)
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
	if !publicationServiceCallsEqual(store.calls, []string{"observe"}) {
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
	if !publicationServiceCallsEqual(store.calls, []string{"observe", "status"}) {
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

	_, err = service.p2Result(context.Background(), fixture.run, nil, nil)
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
		!publicationServiceCallsEqual(store.calls, []string{"observe", "commit", "journal", "observe"}) {
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
	want := []string{"observe", "adopt", "observe", "adopt", "install", "observe"}
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
	prepare          func(ports.PrepareCompositeRequest) (ports.PreparedComposite, error)
	stage            func(ports.StageFinalRequest) (ports.StageFinalResult, error)
	adopt            func(ports.AdoptStagedFinalRequest) (ports.StageFinalResult, error)
	install          func(ports.InstallFinalRequest) (ports.InstallFinalResult, error)
	replace          func(ports.MutableReplaceRequest) (ports.MutableReplaceResult, error)
	commit           func(ports.PreparedComposite) (ports.CompositeCommitResult, error)
	snapshot         func() (ports.CommittedPublicationSnapshot, error)
	diagnostic       func(ports.CorruptionDiagnosticRequest) (ports.CorruptionDiagnosticResult, error)
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

func (store *publicationServiceScriptedStore) ReadAuxiliaryArtifact(context.Context, ports.ReadAuxiliaryArtifactRequest) (ports.ImmutablePublicationArtifact, error) {
	store.calls = append(store.calls, "read_auxiliary")
	return ports.ImmutablePublicationArtifact{}, errors.New("unexpected auxiliary read")
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
