package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const publicationRecoveryActionLimit = 12

var errPublicationReobserve = errors.New("publication post-effect requires re-observation")

// Service owns publication ordering and recovery policy. PublicationStore owns
// only mechanics and durable observation.
type Service struct {
	store     ports.PublicationStore
	validator SchemaValidator
	clock     ports.Clock
	maxBytes  int64
}

// PublicationCommitter is the root-bound publication boundary used by root-review
// orchestration. It deliberately does not expose caller-selected epochs.
type PublicationCommitter interface {
	PublishNext(context.Context, ports.AnchoredRoot, PreparedCandidate) (PublicationResult, error)
}

// PublicationResult is a defensive result of a completed P2 publication or a
// recovery observation that must resume collection. Snapshot is present only
// when P2 is authoritative.
type PublicationResult struct {
	issued           *ports.IssuedReviewID
	final            *ports.FinalReviewIdentity
	decision         domain.PublicationDecision
	exit             *domain.OperationalExitDecision
	snapshot         *ports.CommittedPublicationSnapshot
	supportArtifacts []RunSupportArtifactIdentity
}

// IssuedReviewID returns the post-validation issued ID when this invocation
// created one. Recovery never invents an ID.
func (result PublicationResult) IssuedReviewID() (ports.IssuedReviewID, bool) {
	if result.issued == nil {
		return ports.IssuedReviewID{}, false
	}
	return *result.issued, true
}

// Final returns the immutable final identity when it is known.
func (result PublicationResult) Final() (ports.FinalReviewIdentity, bool) {
	if result.final == nil {
		return ports.FinalReviewIdentity{}, false
	}
	return *result.final, true
}

// Decision returns the app-owned durable classification.
func (result PublicationResult) Decision() domain.PublicationDecision { return result.decision }

// Exit returns the optional exact domain-reduced terminal exit decision. A
// nonterminal P0/P1 recovery result has no exit, so it cannot project a
// zero-value committed-pass outcome.
func (result PublicationResult) Exit() *domain.OperationalExitDecision {
	if result.exit == nil {
		return nil
	}
	exit := *result.exit
	return &exit
}

// TerminalExit returns the terminal exit decision only when this result can
// project one. Normal content exits 0, 1, and 4 are available only from P2.
func (result PublicationResult) TerminalExit() (domain.OperationalExitDecision, bool) {
	if result.exit == nil {
		return domain.OperationalExitDecision{}, false
	}
	return *result.exit, true
}

// Snapshot returns the exact P2 snapshot with defensive byte accessors.
func (result PublicationResult) Snapshot() (ports.CommittedPublicationSnapshot, bool) {
	if result.snapshot == nil {
		return ports.CommittedPublicationSnapshot{}, false
	}
	return *result.snapshot, true
}

// PersistedRunSupportArtifacts returns defensive copies of the exact support
// artifact identities persisted and re-read by this invocation before P2.
func (result PublicationResult) PersistedRunSupportArtifacts() []RunSupportArtifactIdentity {
	return append([]RunSupportArtifactIdentity(nil), result.supportArtifacts...)
}

// PromptManifestArtifact returns the exact persisted prompt-manifest identity
// for one attempt invocation. It fails closed when this result has no verified
// support view, or the attempt/invocation is absent or ambiguous.
func (result PublicationResult) PromptManifestArtifact(
	attemptID domain.AttemptID,
	invocationSequence uint64,
) (RunSupportArtifactIdentity, bool) {
	if result.decision.Authority() != domain.PublicationAuthorityP2 || invocationSequence == 0 {
		return RunSupportArtifactIdentity{}, false
	}
	var match RunSupportArtifactIdentity
	for _, identity := range result.supportArtifacts {
		artifactAttemptID, artifactSequence, ok := identity.promptManifestBinding()
		if !ok || artifactAttemptID != attemptID || artifactSequence != invocationSequence {
			continue
		}
		if match.valid() {
			return RunSupportArtifactIdentity{}, false
		}
		match = identity
	}
	if !match.valid() {
		return RunSupportArtifactIdentity{}, false
	}
	return match, true
}

// NewService constructs a publication state-machine service.
func NewService(
	store ports.PublicationStore,
	validator SchemaValidator,
	clock ports.Clock,
	maxBytes int64,
) (*Service, error) {
	if nilPublicationDependency(store) {
		return nil, fmt.Errorf("publication service: publication store is required")
	}
	if nilPublicationDependency(validator) {
		return nil, fmt.Errorf("publication service: schema validator is required")
	}
	if nilPublicationDependency(clock) {
		return nil, fmt.Errorf("publication service: clock is required")
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("publication service: max bytes must be positive")
	}
	return &Service{store: store, validator: validator, clock: clock, maxBytes: maxBytes}, nil
}

// PublishFollowup prepares and commits the specialized one-role followup in the
// same P2 composite transaction used for every review publication.
func (service *Service) PublishFollowup(
	ctx context.Context,
	artifactRoot ports.AnchoredRoot,
	input FollowupCandidateInput,
	epoch uint64,
) (PublicationResult, error) {
	candidate, err := PrepareFollowupCandidate(input)
	if err != nil {
		return PublicationResult{}, fmt.Errorf("publish followup: %w", err)
	}
	return service.Publish(ctx, artifactRoot, candidate, epoch)
}

// PublishFollowupNext prepares the specialized one-role followup and commits it
// under the next root-scoped epoch selected atomically by the publication store.
func (service *Service) PublishFollowupNext(
	ctx context.Context,
	artifactRoot ports.AnchoredRoot,
	input FollowupCandidateInput,
) (PublicationResult, error) {
	candidate, err := PrepareFollowupCandidate(input)
	if err != nil {
		return PublicationResult{}, fmt.Errorf("publish followup next: %w", err)
	}
	return service.PublishNext(ctx, artifactRoot, candidate)
}

// PublishNext selects and commits the next root-scoped durable epoch as one
// store-authorized transaction. It is the production entry point; Publish
// remains available for compatibility callers that explicitly control epochs.
func (service *Service) PublishNext(
	ctx context.Context,
	artifactRoot ports.AnchoredRoot,
	candidate PreparedCandidate,
) (PublicationResult, error) {
	return service.publishNext(ctx, artifactRoot, candidate, nil)
}

func (service *Service) PublishNextObserved(
	ctx context.Context,
	artifactRoot ports.AnchoredRoot,
	candidate PreparedCandidate,
	observer LifecycleObserver,
) (PublicationResult, error) {
	if observer == nil {
		return PublicationResult{}, publicationFailure("publish-next.observe", domain.FailureConfiguration, "publication lifecycle observer is required", nil)
	}
	return service.publishNext(ctx, artifactRoot, candidate, observer)
}

func (service *Service) publishNext(
	ctx context.Context,
	artifactRoot ports.AnchoredRoot,
	candidate PreparedCandidate,
	observer LifecycleObserver,
) (result PublicationResult, err error) {
	p2Committed := false
	defer func() {
		if err == nil || observer == nil || p2Committed {
			return
		}
		if observationErr := observePublicationLifecycle(ctx, observer, LifecycleFailed, err); observationErr != nil {
			result = PublicationResult{}
			err = errors.Join(err, observationErr)
		}
	}()
	if service == nil {
		return PublicationResult{}, fmt.Errorf("publish next: nil service")
	}
	if err := service.ready(ctx, "publish-next.validate"); err != nil {
		return PublicationResult{}, err
	}
	if !artifactRoot.Valid() || !candidate.Valid() {
		return PublicationResult{}, publicationFailure("publish-next.validate", domain.FailureConfiguration, "invalid publication input", nil)
	}
	committer, ok := service.store.(ports.PublicationEpochCommitStore)
	if !ok {
		return PublicationResult{}, publicationFailure("publish-next.validate", domain.FailureConfiguration, "publication store does not support atomic epoch commits", nil)
	}

	called := false
	err = committer.WithNextPublicationEpoch(ctx, artifactRoot, func(commitCtx context.Context, epoch uint64) error {
		if called {
			return publicationFailure("publish-next.commit", domain.FailureArtifact, "publication store invoked epoch commit callback more than once", nil)
		}
		called = true
		if commitCtx == nil {
			return publicationFailure("publish-next.commit", domain.FailureConfiguration, "publication store supplied nil commit context", nil)
		}
		if epoch == 0 {
			return publicationFailure("publish-next.commit", domain.FailureArtifact, "publication store supplied zero epoch", nil)
		}
		published, publishErr := service.publish(commitCtx, artifactRoot, candidate, epoch, observer)
		if publishErr != nil {
			return publishErr
		}
		result = published
		return nil
	})
	if err != nil {
		var classified *domain.Failure
		if !errors.As(err, &classified) {
			err = service.storeFailure(ctx, "publish-next.lock", "publication store lock failed", err)
		}
		return PublicationResult{}, fmt.Errorf("publish next: %w", err)
	}
	if !called {
		return PublicationResult{}, publicationFailure("publish-next.commit", domain.FailureArtifact, "publication store did not commit an epoch", nil)
	}
	if result.Decision().Authority() == domain.PublicationAuthorityP2 {
		p2Committed = true
		if err := observePublicationLifecycle(ctx, observer, LifecycleCommitted, nil); err != nil {
			return PublicationResult{}, newCommittedDiagnosticFailure(result, err)
		}
	}
	return result, nil
}

// Publish validates a candidate before issuing its ReviewID, writes all
// recoverable material before a journal hint, and returns only after a fresh P2
// observation and snapshot confirm publication authority.
func (service *Service) Publish(
	ctx context.Context,
	artifactRoot ports.AnchoredRoot,
	candidate PreparedCandidate,
	epoch uint64,
) (PublicationResult, error) {
	return service.publish(ctx, artifactRoot, candidate, epoch, nil)
}

func (service *Service) publish(
	ctx context.Context,
	artifactRoot ports.AnchoredRoot,
	candidate PreparedCandidate,
	epoch uint64,
	observer LifecycleObserver,
) (PublicationResult, error) {
	if err := service.ready(ctx, "publish.validate"); err != nil {
		return PublicationResult{}, err
	}
	if !artifactRoot.Valid() || !candidate.Valid() || epoch == 0 {
		return PublicationResult{}, publicationFailure("publish.validate", domain.FailureConfiguration, "invalid publication input", nil)
	}
	run, err := ports.NewPublicationRun(artifactRoot, candidate.SessionID(), candidate.RunID())
	if err != nil {
		return PublicationResult{}, publicationFailure("publish.validate", domain.FailureConfiguration, "invalid publication run", err)
	}
	candidateHash := candidate.ValidatedCandidateSHA256()
	if candidateHash == "" {
		return PublicationResult{}, publicationFailure("publish.validate", domain.FailureConfiguration, "invalid validated candidate", nil)
	}
	if err := observePublicationLifecycle(ctx, observer, LifecyclePreparationStarted, nil); err != nil {
		return PublicationResult{}, err
	}
	if err := service.checkpoint(ctx, "publish.preflight"); err != nil {
		return PublicationResult{}, err
	}
	createdAt := service.clock.Now()
	preflightID, err := domain.ParseReviewID("019f596a-d174-7321-b920-c2d312c82cc2")
	if err != nil {
		return PublicationResult{}, publicationFailure("publish.preflight", domain.FailureInternal, "preflight review ID is invalid", err)
	}
	preflightBundle, err := candidate.Build(ctx, service.validator, preflightID, createdAt, epoch)
	if err != nil {
		return PublicationResult{}, service.classifyBuildFailure(ctx, err)
	}
	if err := validatePublicationBundleSize(preflightBundle, service.maxBytes); err != nil {
		return PublicationResult{}, publicationFailure("publish.preflight", domain.FailureArtifact, "publication bundle exceeds configured byte limits", err)
	}
	if err := service.checkpoint(ctx, "publish.issue_review_id"); err != nil {
		return PublicationResult{}, err
	}
	issueRequest, err := ports.NewIssueReviewIDRequest(run, candidateHash)
	if err != nil {
		return PublicationResult{}, publicationFailure("publish.issue_review_id", domain.FailureConfiguration, "invalid issuance request", err)
	}
	issued, issueErr := service.store.IssueReviewID(ctx, issueRequest)
	if issueErr != nil && issued.Valid() {
		observation, decision, observeErr := service.observe(ctx, run)
		if observeErr != nil {
			return PublicationResult{}, service.storeFailure(
				ctx,
				"publish.issue_review_id",
				"ambiguous review ID issuance could not be reconciled",
				errors.Join(issueErr, observeErr),
			)
		}
		if issued.ValidatedCandidateSHA256() != candidateHash {
			return PublicationResult{}, service.storeFailure(
				ctx,
				"publish.issue_review_id",
				"review ID issuance returned a mismatched binding",
				issueErr,
			)
		}
		if decision.Authority() == domain.PublicationAuthorityP2 {
			return service.p2ResultFromDecision(ctx, run, observation, decision, &issued, nil, true)
		}
		if decision.Action() != domain.RecoveryActionResumeCollection {
			return service.publishIssuedRecovered(ctx, run, issued)
		}
	}
	if !issued.Valid() || issued.ValidatedCandidateSHA256() != candidateHash {
		if issueErr != nil {
			return PublicationResult{}, service.storeFailure(ctx, "publish.issue_review_id", "review ID issuance failed without a valid binding", issueErr)
		}
		return PublicationResult{}, publicationFailure("publish.issue_review_id", domain.FailureArtifact, "store returned inconsistent review ID", nil)
	}

	if err := service.checkpoint(ctx, "publish.build"); err != nil {
		return PublicationResult{}, err
	}
	bundle, err := candidate.Build(ctx, service.validator, issued.ReviewID(), createdAt, epoch)
	if err != nil {
		return PublicationResult{}, service.classifyBuildFailure(ctx, err)
	}
	if !bundle.Valid() {
		return PublicationResult{}, publicationFailure("publish.build", domain.FailureArtifact, "publication bundle is inconsistent", nil)
	}
	if err := validatePublicationBundleSize(bundle, service.maxBytes); err != nil {
		return PublicationResult{}, publicationFailure("publish.build", domain.FailureInternal, "issued publication bundle changed preflight size bounds", err)
	}

	if err := service.checkpoint(ctx, "publish.persist_candidate"); err != nil {
		return PublicationResult{}, err
	}
	candidateRequest, err := ports.NewPersistValidatedCandidateRequest(run, bundle.Final())
	if err != nil {
		return PublicationResult{}, publicationFailure("publish.persist_candidate", domain.FailureInternal, "candidate request is invalid", err)
	}
	candidatePersisted, candidateErr := service.store.PersistValidatedCandidate(ctx, candidateRequest)
	if candidateErr != nil {
		if candidatePersisted.Valid() || candidatePersisted.Durability().Valid() {
			return service.publishRecovered(ctx, run, issued, bundle.Final().Identity())
		}
		return PublicationResult{}, service.storeFailure(ctx, "publish.persist_candidate", "validated candidate persistence failed", candidateErr)
	}
	if candidatePersisted.Durability() != ports.ValidatedCandidateDurable ||
		!persistedCandidateMatches(candidatePersisted, run, bundle.Final()) {
		return PublicationResult{}, publicationFailure("publish.persist_candidate", domain.FailureArtifact, "store returned inconsistent candidate receipt", nil)
	}
	persistedSupportArtifacts := make([]ports.ImmutablePublicationArtifact, 0, len(bundle.SupportArtifacts()))

	for _, support := range bundle.SupportArtifacts() {
		request, err := ports.NewPersistRunSupportArtifactRequest(run, support)
		if err != nil {
			return PublicationResult{}, publicationFailure("publish.persist_support", domain.FailureInternal, "run support request is invalid", err)
		}
		if err := service.checkpoint(ctx, "publish.persist_support"); err != nil {
			return PublicationResult{}, err
		}
		persisted, persistErr := service.store.PersistAuxiliaryArtifact(ctx, request)
		if persistErr != nil {
			if persisted.Valid() || persisted.Durability().Valid() {
				return service.publishRecovered(ctx, run, issued, bundle.Final().Identity())
			}
			return PublicationResult{}, service.storeFailure(ctx, "publish.persist_support", "run support persistence failed", persistErr)
		}
		if persisted.Durability() != ports.AuxiliaryArtifactDurable ||
			!persistedAuxiliaryMatches(persisted, run, support) {
			return PublicationResult{}, publicationFailure("publish.persist_support", domain.FailureArtifact, "store returned inconsistent run support receipt", nil)
		}
		readRequest, err := ports.NewReadRunSupportArtifactRequest(run, support.Path(), support.SHA256(), service.maxBytes)
		if err != nil {
			return PublicationResult{}, publicationFailure("publish.verify_support", domain.FailureInternal, "run support read request is invalid", err)
		}
		observed, readErr := service.store.ReadAuxiliaryArtifact(ctx, readRequest)
		if readErr != nil {
			return PublicationResult{}, service.storeFailure(ctx, "publish.verify_support", "run support verification failed", readErr)
		}
		if !sameImmutableArtifact(observed, support) {
			return PublicationResult{}, publicationFailure("publish.verify_support", domain.FailureArtifact, "store returned inconsistent run support bytes", nil)
		}
		persistedSupportArtifacts = append(persistedSupportArtifacts, observed)
	}

	composite, err := ports.NewCommitCompositeRequest(run, bundle.Final().Identity(), bundle.Manifest(), bundle.LineageEdge(), bundle.Epoch())
	if err != nil {
		return PublicationResult{}, publicationFailure("publish.prepare_composite", domain.FailureInternal, "composite request is invalid", err)
	}
	prepareRequest, err := ports.NewPrepareCompositeRequest(composite)
	if err != nil {
		return PublicationResult{}, publicationFailure("publish.prepare_composite", domain.FailureInternal, "prepared composite request is invalid", err)
	}
	if err := service.checkpoint(ctx, "publish.prepare_composite"); err != nil {
		return PublicationResult{}, err
	}
	prepared, preparedErr := service.store.PrepareComposite(ctx, prepareRequest)
	if preparedErr != nil {
		if prepared.Valid() || prepared.Durability().Valid() {
			return service.publishRecovered(ctx, run, issued, bundle.Final().Identity())
		}
		return PublicationResult{}, service.storeFailure(ctx, "publish.prepare_composite", "composite preparation failed", preparedErr)
	}
	if prepared.Durability() != ports.CompositePreparationDurable ||
		!preparedMatchesComposite(prepared, composite) {
		return PublicationResult{}, publicationFailure("publish.prepare_composite", domain.FailureArtifact, "store returned inconsistent prepared composite", nil)
	}

	journal, err := journalForState(bundle.Journal(), domain.JournalContentValidated)
	if err != nil {
		return PublicationResult{}, publicationFailure("publish.content_validated", domain.FailureInternal, "journal transition is invalid", err)
	}
	if recovered, err := service.replaceJournal(ctx, run, journal, ports.ExpectMutableAbsent()); err != nil {
		return PublicationResult{}, err
	} else if recovered {
		return service.publishRecovered(ctx, run, issued, bundle.Final().Identity())
	}
	contentJournal := journal

	staged, recovered, err := service.stageFinal(ctx, run, issued, bundle.Final(), bundle.StagedFinal().Path())
	if err != nil {
		return PublicationResult{}, err
	}
	if recovered {
		return service.publishRecovered(ctx, run, issued, bundle.Final().Identity())
	}
	if err := observePublicationLifecycle(ctx, observer, LifecycleStaged, nil); err != nil {
		return PublicationResult{}, err
	}
	journal, err = journalForState(bundle.Journal(), domain.JournalFinalStaged)
	if err != nil {
		return PublicationResult{}, publicationFailure("publish.final_staged", domain.FailureInternal, "journal transition is invalid", err)
	}
	if recovered, err := service.replaceJournal(ctx, run, journal, expectationForDocument(contentJournal)); err != nil {
		return PublicationResult{}, err
	} else if recovered {
		return service.publishRecovered(ctx, run, issued, bundle.Final().Identity())
	}
	stagedJournal := journal

	if err := service.checkpoint(ctx, "publish.install_final"); err != nil {
		return PublicationResult{}, err
	}
	installRequest := mustInstallRequest(run, staged)
	installed, installErr := service.store.InstallFinal(ctx, installRequest)
	if installErr != nil {
		if installed.Valid() || installed.Durability().Valid() {
			return service.publishRecovered(ctx, run, issued, bundle.Final().Identity())
		}
		return PublicationResult{}, service.storeFailure(ctx, "publish.install_final", "final installation failed", installErr)
	}
	if installed.Durability() != ports.InstallFinalDurable ||
		!installedFinalMatches(installed, run, bundle.Final()) {
		return PublicationResult{}, publicationFailure("publish.install_final", domain.FailureArtifact, "store returned inconsistent final receipt", nil)
	}
	if err := observePublicationLifecycle(ctx, observer, LifecycleInstalled, nil); err != nil {
		return PublicationResult{}, err
	}
	journal, err = journalForState(bundle.Journal(), domain.JournalFinalFileInstalled)
	if err != nil {
		return PublicationResult{}, publicationFailure("publish.final_installed", domain.FailureInternal, "journal transition is invalid", err)
	}
	if recovered, err := service.replaceJournal(ctx, run, journal, expectationForDocument(stagedJournal)); err != nil {
		return PublicationResult{}, err
	} else if recovered {
		return service.publishRecovered(ctx, run, issued, bundle.Final().Identity())
	}
	installedJournal := journal

	if err := service.checkpoint(ctx, "publish.commit_composite"); err != nil {
		return PublicationResult{}, err
	}
	committed, commitErr := service.store.CommitPreparedComposite(ctx, prepared)
	if commitErr != nil {
		if committed.Valid() || committed.Phase().Valid() {
			return service.publishRecovered(ctx, run, issued, bundle.Final().Identity())
		}
		return PublicationResult{}, service.storeFailure(ctx, "publish.commit_composite", "prepared composite commit failed", commitErr)
	}
	if !committed.Valid() || !commitMatchesPreparedComposite(committed, prepared) ||
		committed.Phase() != ports.CompositeCommittedDurable {
		return PublicationResult{}, publicationFailure("publish.commit_composite", domain.FailureArtifact, "store returned inconsistent prepared composite commit", nil)
	}
	journal, err = journalForState(bundle.Journal(), domain.JournalManifestCommitted)
	if err != nil {
		return PublicationResult{}, publicationFailure("publish.manifest_committed", domain.FailureInternal, "journal transition is invalid", err)
	}
	if recovered, err := service.replaceJournal(ctx, run, journal, expectationForDocument(installedJournal)); err != nil {
		return PublicationResult{}, err
	} else if recovered {
		return service.publishRecovered(ctx, run, issued, bundle.Final().Identity())
	}
	manifestJournal := journal

	if recovered, err := service.replaceStatus(ctx, run, bundle.Status(), ports.ExpectMutableAbsent()); err != nil {
		return PublicationResult{}, err
	} else if recovered {
		return service.publishRecovered(ctx, run, issued, bundle.Final().Identity())
	}
	journal, err = journalForState(bundle.Journal(), domain.JournalCompleted)
	if err != nil {
		return PublicationResult{}, publicationFailure("publish.completed", domain.FailureInternal, "journal transition is invalid", err)
	}
	if recovered, err := service.replaceJournal(ctx, run, journal, expectationForDocument(manifestJournal)); err != nil {
		return PublicationResult{}, err
	} else if recovered {
		return service.publishRecovered(ctx, run, issued, bundle.Final().Identity())
	}
	final := bundle.Final().Identity()
	return service.p2Result(ctx, run, &issued, &final, persistedSupportArtifacts)
}

// Recover applies only the action selected by a fresh domain classification.
// It never adopts ambiguous files, regenerates final/composite bytes, or
// downgrades P2 authority.
func (service *Service) Recover(ctx context.Context, run ports.PublicationRun) (PublicationResult, error) {
	if err := service.ready(ctx, "recover.observe"); err != nil {
		return PublicationResult{}, err
	}
	if !run.Valid() {
		return PublicationResult{}, publicationFailure("recover.observe", domain.FailureConfiguration, "invalid publication run", nil)
	}
	for attempt := 0; attempt < publicationRecoveryActionLimit; attempt++ {
		observation, decision, err := service.observe(ctx, run)
		if err != nil {
			return PublicationResult{}, err
		}
		switch decision.Action() {
		case domain.RecoveryActionResumeCollection:
			return PublicationResult{decision: decision}, nil
		case domain.RecoveryActionReconstructCompletedStatus:
			result, err := service.p2ResultFromDecision(ctx, run, observation, decision, nil, nil, true)
			if err != nil {
				return result, err
			}
			snapshot, ok := result.Snapshot()
			if !ok {
				return service.p2RecoveryFailure(ctx, result, "recover.reconstruct", "P2 result omitted committed snapshot", nil)
			}
			changed, err := service.reconstructCompletedStatus(ctx, run, observation, snapshot)
			if err != nil {
				return service.p2RecoveryFailure(ctx, result, "recover.reconstruct", "completed status reconstruction failed", err)
			}
			if changed {
				continue
			}
			return result, nil
		case domain.RecoveryActionEmitImmutableCorruptionDiagnostic:
			artifactExit := artifactExit(decision.Reasons())
			if err := service.writeDiagnostic(ctx, run, observation, decision); err != nil {
				if errors.Is(err, ports.ErrCorruptionObservationStale) ||
					errors.Is(err, errPublicationReobserve) {
					continue
				}
				exit := combineExitDecisions(artifactExit, publicationExitFromError(err))
				return PublicationResult{decision: decision, exit: &exit}, err
			}
			return PublicationResult{decision: decision, exit: &artifactExit}, publicationFailure("recover.corruption", domain.FailureArtifact, "publication corruption observed", nil)
		}

		material, ok := observation.RecoveryMaterial()
		if !ok {
			return PublicationResult{}, publicationFailure("recover.material", domain.FailureArtifact, "recovery observation omitted material", nil)
		}
		prepared, ok := material.PreparedComposite()
		if !ok {
			return PublicationResult{}, publicationFailure("recover.material", domain.FailureArtifact, "recovery observation omitted prepared composite", nil)
		}
		candidate, ok := material.ValidatedCandidate()
		if !ok {
			return PublicationResult{}, publicationFailure("recover.material", domain.FailureArtifact, "recovery observation omitted validated candidate", nil)
		}
		if err := validateRecoveryMaterial(run, observation, material, candidate, prepared); err != nil {
			return PublicationResult{}, publicationFailure("recover.material", domain.FailureArtifact, "recovery material is inconsistent", err)
		}

		switch decision.Action() {
		case domain.RecoveryActionRestageValidatedCandidate:
			stagedPath, err := canonicalStagedFinalPath(run, candidate.Identity())
			if err != nil {
				return PublicationResult{}, publicationFailure("recover.restage", domain.FailureInternal, "staged path is invalid", err)
			}
			issued, err := issuedReviewIDFromMaterial(material, candidate, prepared)
			if err != nil {
				return PublicationResult{}, publicationFailure("recover.restage", domain.FailureArtifact, "candidate review ID binding is invalid", err)
			}
			_, recovered, err := service.stageFinal(ctx, run, issued, candidate, stagedPath)
			if err != nil {
				return PublicationResult{}, err
			}
			if recovered {
				continue
			}
			if observation.ClassifierInput().JournalState() == domain.JournalContentValidated {
				journal, err := observedJournalForState(material.Journal(), domain.JournalFinalStaged)
				if err != nil {
					return PublicationResult{}, publicationFailure("recover.final_staged", domain.FailureArtifact, "journal transition is invalid", err)
				}
				_, err = service.replaceJournal(ctx, run, journal, expectationForObserved(material.Journal()))
				if err != nil {
					return PublicationResult{}, err
				}
			}
		case domain.RecoveryActionInstallStagedFinal:
			stagedPath, ok := material.StagedPath()
			if !ok {
				return PublicationResult{}, publicationFailure(
					"recover.install",
					domain.FailureArtifact,
					"recovered staged final has no staged path",
					nil,
				)
			}
			issued, err := issuedReviewIDFromMaterial(material, candidate, prepared)
			if err != nil {
				return PublicationResult{}, publicationFailure(
					"recover.install",
					domain.FailureArtifact,
					"candidate review ID binding is invalid",
					err,
				)
			}
			binding, err := ports.NewIssuedFinalBinding(issued, candidate.Identity())
			if err != nil {
				return PublicationResult{}, publicationFailure(
					"recover.install",
					domain.FailureArtifact,
					"candidate review ID binding is invalid",
					err,
				)
			}
			adoptRequest, err := ports.NewAdoptStagedFinalRequest(
				run,
				stagedPath,
				binding,
				candidate,
				service.maxBytes,
			)
			if err != nil {
				return PublicationResult{}, publicationFailure(
					"recover.install",
					domain.FailureArtifact,
					"staged durability request is invalid",
					err,
				)
			}
			staged, adoptErr := service.store.AdoptStagedFinal(ctx, adoptRequest)
			if adoptErr != nil {
				if staged.Valid() || staged.Durability().Valid() {
					continue
				}
				return PublicationResult{}, service.storeFailure(
					ctx,
					"recover.install",
					"staged durability adoption failed",
					adoptErr,
				)
			}
			if staged.Durability() != ports.StageFinalDurable ||
				!stagedFinalMatches(staged, run, candidate, stagedPath) {
				return PublicationResult{}, publicationFailure(
					"recover.install",
					domain.FailureArtifact,
					"store returned inconsistent staged durability proof",
					nil,
				)
			}
			installRequest := mustInstallRequest(run, staged)
			installed, installErr := service.store.InstallFinal(ctx, installRequest)
			if installErr != nil {
				if installed.Valid() || installed.Durability().Valid() {
					continue
				}
				return PublicationResult{}, service.storeFailure(
					ctx,
					"recover.install",
					"final installation failed",
					installErr,
				)
			}
			if installed.Durability() != ports.InstallFinalDurable ||
				!installedFinalMatches(installed, run, candidate) {
				return PublicationResult{}, publicationFailure(
					"recover.install",
					domain.FailureArtifact,
					"store returned inconsistent final receipt",
					nil,
				)
			}
			continue
		case domain.RecoveryActionCommitCompositeEpoch:
			if err := service.checkpoint(ctx, "recover.commit_composite"); err != nil {
				return PublicationResult{}, err
			}
			committed, commitErr := service.store.CommitPreparedComposite(ctx, prepared)
			if commitErr != nil {
				if committed.Valid() || committed.Phase().Valid() {
					continue
				}
				return PublicationResult{}, service.storeFailure(ctx, "recover.commit_composite", "prepared composite commit failed", commitErr)
			}
			if !committed.Valid() || !commitMatchesPreparedComposite(committed, prepared) ||
				committed.Phase() != ports.CompositeCommittedDurable {
				return PublicationResult{}, publicationFailure("recover.commit_composite", domain.FailureArtifact, "store returned inconsistent prepared composite commit", nil)
			}
			journal, err := observedJournalForState(material.Journal(), domain.JournalManifestCommitted)
			if err != nil {
				return PublicationResult{}, publicationFailure("recover.manifest_committed", domain.FailureArtifact, "journal transition is invalid", err)
			}
			_, err = service.replaceJournal(ctx, run, journal, expectationForObserved(material.Journal()))
			if err != nil {
				return PublicationResult{}, err
			}
		default:
			return PublicationResult{}, publicationFailure("recover.classify", domain.FailureArtifact, "unsupported recovery action", nil)
		}
	}
	return PublicationResult{}, publicationFailure("recover", domain.FailureArtifact, "recovery action limit exceeded", nil)
}

func (service *Service) publishRecovered(ctx context.Context, run ports.PublicationRun, issued ports.IssuedReviewID, final ports.FinalReviewIdentity) (PublicationResult, error) {
	result, err := service.Recover(ctx, run)
	if err != nil {
		return result, err
	}
	recoveredFinal, finalOK := result.Final()
	snapshot, snapshotOK := result.Snapshot()
	if result.Decision().Authority() != domain.PublicationAuthorityP2 || !finalOK || !snapshotOK ||
		recoveredFinal != final || issued.ReviewID() != recoveredFinal.ReviewID() {
		return service.p2RecoveryFailure(ctx, result, "publish.recover", "recovery did not reach the issued P2 final", nil)
	}
	recoveredCandidateSHA256, bindingErr := committedSnapshotValidatedCandidateSHA256(snapshot)
	if bindingErr != nil || !issued.Valid() || issued.ValidatedCandidateSHA256() != recoveredCandidateSHA256 {
		return service.p2RecoveryFailure(ctx, result, "publish.recover", "recovery candidate binding does not match issued review ID", bindingErr)
	}
	issuedCopy := issued
	result.issued = &issuedCopy
	return result, nil
}

func (service *Service) publishIssuedRecovered(ctx context.Context, run ports.PublicationRun, issued ports.IssuedReviewID) (PublicationResult, error) {
	result, err := service.Recover(ctx, run)
	if err != nil {
		return result, err
	}
	recoveredFinal, finalOK := result.Final()
	snapshot, snapshotOK := result.Snapshot()
	if result.Decision().Authority() != domain.PublicationAuthorityP2 || !finalOK || !snapshotOK ||
		issued.ReviewID() != recoveredFinal.ReviewID() {
		return service.p2RecoveryFailure(ctx, result, "publish.recover", "recovery did not reach the issued P2 final", nil)
	}
	recoveredCandidateSHA256, bindingErr := committedSnapshotValidatedCandidateSHA256(snapshot)
	if bindingErr != nil || !issued.Valid() || issued.ValidatedCandidateSHA256() != recoveredCandidateSHA256 {
		return service.p2RecoveryFailure(ctx, result, "publish.recover", "recovery candidate binding does not match issued review ID", bindingErr)
	}
	issuedCopy := issued
	result.issued = &issuedCopy
	return result, nil
}

func (service *Service) stageFinal(ctx context.Context, run ports.PublicationRun, issued ports.IssuedReviewID, final ports.FinalReviewArtifact, stagedPath ports.SafeRelativePath) (ports.StageFinalResult, bool, error) {
	if err := service.checkpoint(ctx, "publication.stage"); err != nil {
		return ports.StageFinalResult{}, false, err
	}
	binding, err := ports.NewIssuedFinalBinding(issued, final.Identity())
	if err != nil {
		return ports.StageFinalResult{}, false, publicationFailure("publication.stage", domain.FailureInternal, "issued final binding is invalid", err)
	}
	finalBytes := final.Bytes()
	request, err := ports.NewStageFinalRequestWithExpectedByteLength(
		run,
		stagedPath,
		binding,
		bytes.NewReader(finalBytes),
		service.maxBytes,
		int64(len(finalBytes)),
		[]string{"validated_candidate"},
		func(error) {},
	)
	if err != nil {
		return ports.StageFinalResult{}, false, publicationFailure("publication.stage", domain.FailureInternal, "stage request is invalid", err)
	}
	staged, stageErr := service.store.StageFinal(ctx, request)
	if stageErr != nil {
		if staged.Valid() || staged.Durability().Valid() {
			return staged, true, nil
		}
		return ports.StageFinalResult{}, false, service.storeFailure(ctx, "publication.stage", "final staging failed", stageErr)
	}
	if staged.Durability() != ports.StageFinalDurable ||
		!stagedFinalMatches(staged, run, final, stagedPath) {
		return ports.StageFinalResult{}, false, publicationFailure("publication.stage", domain.FailureArtifact, "store returned inconsistent staged receipt", nil)
	}
	return staged, false, nil
}

func (service *Service) replaceJournal(ctx context.Context, run ports.PublicationRun, document PublicationDocument, expectation ports.MutableCASExpectation) (bool, error) {
	if err := service.checkpoint(ctx, "publication.journal"); err != nil {
		return false, err
	}
	request, err := ports.NewMutableReplaceRequest(run, ports.MutablePublicationJournal, document.Path(), expectation, document.Bytes(), document.SHA256())
	if err != nil {
		return false, publicationFailure("publication.journal", domain.FailureInternal, "journal replace request is invalid", err)
	}
	result, replaceErr := service.store.ReplaceMutable(ctx, request)
	if replaceErr != nil {
		if errors.Is(replaceErr, ports.ErrMutableCASConflict) ||
			result.Valid() || result.Durability().Valid() {
			return true, nil
		}
		return false, service.storeFailure(ctx, "publication.journal", "journal replacement failed", replaceErr)
	}
	if result.Durability() != ports.MutableReplaceDurable ||
		!mutableReplacementMatches(result, run, request) {
		return false, publicationFailure("publication.journal", domain.FailureArtifact, "store returned inconsistent journal receipt", nil)
	}
	return false, nil
}

func (service *Service) replaceStatus(ctx context.Context, run ports.PublicationRun, document PublicationDocument, expectation ports.MutableCASExpectation) (bool, error) {
	if err := service.checkpoint(ctx, "publication.status"); err != nil {
		return false, err
	}
	request, err := ports.NewMutableReplaceRequest(run, ports.MutablePublicationStatus, document.Path(), expectation, document.Bytes(), document.SHA256())
	if err != nil {
		return false, publicationFailure("publication.status", domain.FailureInternal, "status replace request is invalid", err)
	}
	result, replaceErr := service.store.ReplaceMutable(ctx, request)
	if replaceErr != nil {
		if errors.Is(replaceErr, ports.ErrMutableCASConflict) ||
			result.Valid() || result.Durability().Valid() {
			return true, nil
		}
		return false, service.storeFailure(ctx, "publication.status", "status replacement failed", replaceErr)
	}
	if result.Durability() != ports.MutableReplaceDurable ||
		!mutableReplacementMatches(result, run, request) {
		return false, publicationFailure("publication.status", domain.FailureArtifact, "store returned inconsistent status receipt", nil)
	}
	return false, nil
}

func (service *Service) p2Result(
	ctx context.Context,
	run ports.PublicationRun,
	issued *ports.IssuedReviewID,
	final *ports.FinalReviewIdentity,
	supportArtifacts []ports.ImmutablePublicationArtifact,
) (PublicationResult, error) {
	observation, decision, err := service.observe(ctx, run)
	if err != nil {
		return PublicationResult{}, err
	}
	result, err := service.p2ResultFromDecision(ctx, run, observation, decision, issued, final, false)
	if err != nil {
		return result, err
	}
	result.supportArtifacts = make([]RunSupportArtifactIdentity, len(supportArtifacts))
	for index, artifact := range supportArtifacts {
		result.supportArtifacts[index] = runSupportArtifactIdentity(artifact)
	}
	return result, nil
}

func (service *Service) p2ResultFromDecision(
	ctx context.Context,
	run ports.PublicationRun,
	observation ports.PublicationObservation,
	decision domain.PublicationDecision,
	issued *ports.IssuedReviewID,
	final *ports.FinalReviewIdentity,
	reloadSupportArtifacts bool,
) (PublicationResult, error) {
	if !observation.Valid() || !decision.Valid() {
		return PublicationResult{}, publicationFailure("publication.p2", domain.FailureArtifact, "P2 observation or decision is invalid", nil)
	}
	observedDecision, err := domain.ClassifyPublication(observation.ClassifierInput())
	if err != nil {
		return PublicationResult{}, publicationFailure("publication.p2", domain.FailureArtifact, "P2 observation could not be classified", err)
	}
	if !reflect.DeepEqual(observedDecision, decision) {
		return PublicationResult{}, publicationFailure("publication.p2", domain.FailureArtifact, "P2 decision does not match the observation", nil)
	}
	if decision.Authority() != domain.PublicationAuthorityP2 || decision.Status() != domain.PublicationCommitted {
		return PublicationResult{decision: decision}, publicationFailure("publication.p2", domain.FailureArtifact, "P2 authority was not observed", nil)
	}
	storedExit, ok := decision.ExitCode()
	if !ok {
		return PublicationResult{}, publicationFailure("publication.p2", domain.FailureArtifact, "P2 observation omitted normal exit", nil)
	}
	material, ok := observation.RecoveryMaterial()
	if !ok {
		return PublicationResult{}, publicationFailure("publication.snapshot", domain.FailureArtifact, "P2 observation omitted recovery material", nil)
	}
	snapshot, ok := material.CommittedSnapshot()
	if !ok || !snapshot.Valid() {
		return PublicationResult{}, publicationFailure("publication.snapshot", domain.FailureArtifact, "P2 observation omitted a valid committed snapshot", nil)
	}
	snapshotExit, err := validateCommittedSnapshotSemantics(run, snapshot)
	if err != nil {
		return PublicationResult{}, publicationFailure("publication.snapshot", domain.FailureArtifact, "committed snapshot semantics are inconsistent", err)
	}
	if snapshotExit != storedExit {
		return PublicationResult{}, publicationFailure("publication.snapshot", domain.FailureArtifact, "committed snapshot exit does not match the P2 observation", nil)
	}
	exitReasons, err := committedExitReasons(snapshot, storedExit)
	if err != nil {
		return PublicationResult{}, publicationFailure("publication.p2", domain.FailureArtifact, "normal exit reason is invalid", err)
	}
	exit, err := reduceExitReasons(exitReasons)
	if err != nil {
		return PublicationResult{}, publicationFailure("publication.p2", domain.FailureInternal, "normal exit reduction failed", err)
	}
	snapshotCandidateSHA256, err := committedSnapshotValidatedCandidateSHA256(snapshot)
	if err != nil {
		return PublicationResult{}, publicationFailure("publication.snapshot", domain.FailureArtifact, "committed snapshot candidate binding is invalid", err)
	}
	snapshotFinal := snapshot.Final().Identity()
	if issued != nil && (!issued.Valid() ||
		issued.ReviewID() != snapshotFinal.ReviewID() ||
		issued.ValidatedCandidateSHA256() != snapshotCandidateSHA256) {
		return PublicationResult{}, publicationFailure("publication.snapshot", domain.FailureArtifact, "issued review ID does not match committed snapshot", nil)
	}
	if final != nil && *final != snapshotFinal {
		return PublicationResult{}, publicationFailure("publication.snapshot", domain.FailureArtifact, "caller final does not match committed snapshot", nil)
	}
	result := PublicationResult{decision: decision, exit: &exit, snapshot: &snapshot, final: &snapshotFinal}
	if reloadSupportArtifacts {
		supportArtifacts, err := service.readManifestBoundSupportArtifacts(ctx, run, snapshot)
		if err != nil {
			return service.p2RecoveryFailure(ctx, result, "publication.support", "committed support inventory is invalid", err)
		}
		result.supportArtifacts = supportArtifacts
	}
	if issued != nil {
		issuedCopy := *issued
		result.issued = &issuedCopy
	}
	return result, nil
}

func committedExitReasons(snapshot ports.CommittedPublicationSnapshot, code domain.OperationalExitCode) ([]domain.ExitReason, error) {
	if code == domain.ExitCommittedPass {
		reason, err := domain.NewExitReason(domain.ExitCommittedPass, "publication_committed")
		if err != nil {
			return nil, err
		}
		return []domain.ExitReason{reason}, nil
	}
	var manifest runManifestWire
	if err := json.Unmarshal(snapshot.Manifest().Bytes(), &manifest); err != nil {
		return nil, err
	}
	reasons := make([]domain.ExitReason, 0, len(manifest.Failures)+len(manifest.CIReasonCodes))
	seen := make(map[string]struct{}, cap(reasons))
	appendReason := func(exitCode domain.OperationalExitCode, reasonCode string) error {
		if !validReasonCode(reasonCode) {
			return nil
		}
		key := fmt.Sprintf("%d:%s", exitCode, reasonCode)
		if _, duplicate := seen[key]; duplicate {
			return nil
		}
		reason, err := domain.NewExitReason(exitCode, reasonCode)
		if err != nil {
			return err
		}
		seen[key] = struct{}{}
		reasons = append(reasons, reason)
		return nil
	}
	if code == domain.ExitIncompleteCoverage {
		terminalReasons := terminalManifestFailureReasons(manifest)
		if len(terminalReasons) == 0 {
			return nil, fmt.Errorf("incomplete coverage manifest has no terminal role failure reason")
		}
		for _, reasonCode := range terminalReasons {
			reason, err := domain.NewExitReason(domain.ExitIncompleteCoverage, reasonCode)
			if err != nil {
				return nil, err
			}
			reasons = append(reasons, reason)
		}
		for _, reason := range manifest.CIReasonCodes {
			exitCode := domain.ExitCommittedCIRejected
			if reason == "required_role_incomplete" {
				exitCode = domain.ExitIncompleteCoverage
			}
			if err := appendReason(exitCode, reason); err != nil {
				return nil, err
			}
		}
		return reasons, nil
	}
	if code == domain.ExitCommittedCIRejected {
		for _, reason := range manifest.CIReasonCodes {
			if err := appendReason(domain.ExitCommittedCIRejected, reason); err != nil {
				return nil, err
			}
		}
		if len(reasons) == 0 {
			return nil, fmt.Errorf("CI-rejected manifest has no policy reason")
		}
		return reasons, nil
	}
	return nil, fmt.Errorf("unsupported committed exit")
}

func terminalManifestFailureReasons(manifest runManifestWire) []string {
	finalAttemptByRole := make(map[string]string, len(manifest.SelectedRoles))
	attemptByID := make(map[string]manifestAttemptWire, len(manifest.Attempts))
	for _, attempt := range manifest.Attempts {
		attemptByID[attempt.AttemptID] = attempt
		finalAttemptByRole[attempt.Role] = attempt.AttemptID
	}
	reasons := make([]string, 0, len(manifest.SelectedRoles))
	for _, role := range manifest.SelectedRoles {
		finalAttemptID, present := finalAttemptByRole[role]
		if !present {
			continue
		}
		attempt := attemptByID[finalAttemptID]
		if attempt.State == string(domain.AttemptSucceeded) {
			continue
		}
		for _, failure := range manifest.Failures {
			if failure.AttemptID != nil && *failure.AttemptID == finalAttemptID && validReasonCode(failure.ReasonCode) {
				reasons = append(reasons, failure.ReasonCode)
				break
			}
		}
	}
	return reasons
}
func (service *Service) readManifestBoundSupportArtifacts(
	ctx context.Context,
	run ports.PublicationRun,
	snapshot ports.CommittedPublicationSnapshot,
) ([]RunSupportArtifactIdentity, error) {
	var manifest runManifestWire
	if err := unmarshalCanonicalPublicationRecord(snapshot.Manifest().Bytes(), &manifest, "committed manifest"); err != nil {
		return nil, publicationFailure("publication.support", domain.FailureArtifact, "committed manifest is invalid", err)
	}
	index := manifest.CompositeIdentity.SupportIndex
	if !validSHA256(index.SHA256) {
		return nil, publicationFailure("publication.support", domain.FailureArtifact, "committed manifest support index is invalid", nil)
	}
	indexPath, err := ports.NewSafeRelativePath(index.Path)
	if err != nil {
		return nil, publicationFailure("publication.support", domain.FailureArtifact, "committed manifest support index path is invalid", err)
	}
	readIndex, err := ports.NewReadRunSupportArtifactRequest(run, indexPath, index.SHA256, service.maxBytes)
	if err != nil {
		return nil, publicationFailure("publication.support", domain.FailureArtifact, "committed manifest support index request is invalid", err)
	}
	indexArtifact, err := service.store.ReadAuxiliaryArtifact(ctx, readIndex)
	if err != nil {
		return nil, service.storeFailure(ctx, "publication.support", "committed manifest support index read failed", err)
	}
	if !indexArtifact.Valid() || indexArtifact.Path() != indexPath || indexArtifact.SHA256() != index.SHA256 {
		return nil, publicationFailure("publication.support", domain.FailureArtifact, "committed manifest support index does not match", nil)
	}
	var supportIndex runSupportIndexWire
	if err := unmarshalCanonicalPublicationRecord(indexArtifact.Bytes(), &supportIndex, "committed support index"); err != nil {
		return nil, publicationFailure("publication.support", domain.FailureArtifact, "committed support index is invalid", err)
	}
	if supportIndex.SchemaVersion != "mulgae-run-support-index.v1" {
		return nil, publicationFailure("publication.support", domain.FailureArtifact, "committed support index schema is invalid", nil)
	}
	identities := make([]RunSupportArtifactIdentity, 0, len(supportIndex.Artifacts)+1)
	identities = append(identities, runSupportArtifactIdentity(indexArtifact))
	seen := map[string]struct{}{indexPath.String(): {}}
	for _, item := range supportIndex.Artifacts {
		if !validSHA256(item.SHA256) {
			return nil, publicationFailure("publication.support", domain.FailureArtifact, "committed support identity is invalid", nil)
		}
		path, err := ports.NewSafeRelativePath(item.Path)
		if err != nil {
			return nil, publicationFailure("publication.support", domain.FailureArtifact, "committed support path is invalid", err)
		}
		if _, duplicate := seen[path.String()]; duplicate {
			return nil, publicationFailure("publication.support", domain.FailureArtifact, "committed support paths are ambiguous", nil)
		}
		seen[path.String()] = struct{}{}
		request, err := ports.NewReadRunSupportArtifactRequest(run, path, item.SHA256, service.maxBytes)
		if err != nil {
			return nil, publicationFailure("publication.support", domain.FailureArtifact, "committed support read request is invalid", err)
		}
		artifact, err := service.store.ReadAuxiliaryArtifact(ctx, request)
		if err != nil {
			return nil, service.storeFailure(ctx, "publication.support", "committed support read failed", err)
		}
		if !artifact.Valid() || artifact.Path() != path || artifact.SHA256() != item.SHA256 {
			return nil, publicationFailure("publication.support", domain.FailureArtifact, "committed support artifact does not match", nil)
		}
		identities = append(identities, runSupportArtifactIdentity(artifact))
	}
	return identities, nil
}
func (service *Service) p2RecoveryFailure(
	ctx context.Context,
	result PublicationResult,
	stage string,
	reason string,
	cause error,
) (PublicationResult, error) {
	recoveryErr := publicationFailureFromCause(ctx, stage, domain.FailureArtifact, reason, cause)
	storedExit := result.Exit()
	recoveryExit := publicationExitFromError(recoveryErr)
	if storedExit == nil || recoveryExit == nil {
		result.exit = nil
		return result, recoveryErr
	}
	exit := combineExitDecisions(*storedExit, recoveryExit)
	result.exit = &exit
	return result, recoveryErr
}

func committedSnapshotValidatedCandidateSHA256(snapshot ports.CommittedPublicationSnapshot) (string, error) {
	var manifest runManifestWire
	if err := unmarshalCanonicalPublicationRecord(snapshot.Manifest().Bytes(), &manifest, "committed manifest"); err != nil {
		return "", err
	}
	candidateSHA256 := manifest.RecoveryJournal.ValidatedCandidateSHA256
	if !validSHA256(candidateSHA256) {
		return "", fmt.Errorf("manifest candidate binding is invalid")
	}
	return candidateSHA256, nil
}

func (service *Service) reconstructCompletedStatus(
	ctx context.Context,
	run ports.PublicationRun,
	observation ports.PublicationObservation,
	snapshot ports.CommittedPublicationSnapshot,
) (bool, error) {
	material, ok := observation.RecoveryMaterial()
	if !ok || !material.Valid() || !sameFinalArtifact(material.Final(), snapshot.Final()) {
		return false, publicationFailure(
			"recover.reconstruct",
			domain.FailureArtifact,
			"P2 observation omitted exact mutable recovery material",
			nil,
		)
	}
	status, completedJournal, err := completedRecoveryDocuments(run, snapshot)
	if err != nil {
		return false, publicationFailure("recover.reconstruct", domain.FailureArtifact, "P2 recovery documents are inconsistent", err)
	}

	changed := false
	observedStatus, hasStatus := material.Status()
	if hasStatus && observedStatus.Path() != status.Path() {
		return false, publicationFailure("recover.reconstruct", domain.FailureArtifact, "observed status path is not canonical", nil)
	}
	if !hasStatus || !observedStatus.Present() ||
		observedStatus.SHA256() != status.SHA256() ||
		!bytes.Equal(observedStatus.Bytes(), status.Bytes()) {
		expectation := ports.ExpectMutableAbsent()
		if hasStatus && observedStatus.Present() {
			expectation, err = ports.ExpectMutableSHA256(observedStatus.SHA256())
			if err != nil {
				return false, publicationFailure("recover.reconstruct", domain.FailureInternal, "status CAS expectation is invalid", err)
			}
		}
		uncertain, err := service.replaceStatus(ctx, run, status, expectation)
		if err != nil {
			return false, err
		}
		if uncertain {
			return true, nil
		}
		changed = true
	}

	observedJournal := material.Journal()
	if observedJournal.Path() != completedJournal.Path() {
		return false, publicationFailure("recover.reconstruct", domain.FailureArtifact, "observed journal path is not canonical", nil)
	}
	if !observedJournal.Present() ||
		observedJournal.SHA256() != completedJournal.SHA256() ||
		!bytes.Equal(observedJournal.Bytes(), completedJournal.Bytes()) {
		expectation := expectationForObserved(observedJournal)
		uncertain, err := service.replaceJournal(ctx, run, completedJournal, expectation)
		if err != nil {
			return false, err
		}
		if uncertain {
			return true, nil
		}
		changed = true
	}
	return changed, nil
}

func completedRecoveryDocuments(
	run ports.PublicationRun,
	snapshot ports.CommittedPublicationSnapshot,
) (PublicationDocument, PublicationDocument, error) {
	if !run.Valid() || !snapshot.Valid() {
		return PublicationDocument{}, PublicationDocument{}, fmt.Errorf("invalid run or snapshot")
	}
	if _, err := validateCommittedSnapshotSemantics(run, snapshot); err != nil {
		return PublicationDocument{}, PublicationDocument{}, fmt.Errorf("committed snapshot semantics: %w", err)
	}
	var manifest runManifestWire
	manifestBytes := snapshot.Manifest().Bytes()
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return PublicationDocument{}, PublicationDocument{}, fmt.Errorf("decode committed manifest: %w", err)
	}
	canonicalManifest, err := marshalCanonical(manifest)
	if err != nil {
		return PublicationDocument{}, PublicationDocument{}, fmt.Errorf("canonicalize committed manifest: %w", err)
	}
	if !bytes.Equal(canonicalManifest, manifestBytes) {
		return PublicationDocument{}, PublicationDocument{}, fmt.Errorf("committed manifest is not canonical")
	}

	final := snapshot.Final().Identity()
	epoch := snapshot.Epoch()
	paths, err := publicationPaths(run.SessionID(), run.RunID(), final.ReviewID(), epoch.Value())
	if err != nil {
		return PublicationDocument{}, PublicationDocument{}, err
	}
	normalExit := domain.OperationalExitCode(manifest.ExitCode)
	if manifest.SchemaVersion != "mulgae-run-manifest.v1" ||
		manifest.SessionID != run.SessionID().String() ||
		manifest.RunID != run.RunID().String() ||
		manifest.PersistedJournalState != string(domain.JournalManifestCommitted) ||
		manifest.DurableObservationClass != string(domain.DurableObservationP2Committed) ||
		manifest.DerivedPublicationStatus != string(domain.PublicationCommitted) ||
		manifest.PublicationAuthority != string(domain.PublicationAuthorityP2) ||
		manifest.FinalReview.ReviewID != final.ReviewID().String() ||
		manifest.FinalReview.Path != final.Path().String() ||
		manifest.FinalReview.SHA256 != final.SHA256() ||
		manifest.RecoveryJournal.ExpectedStaged.Path != paths.staged.String() ||
		manifest.RecoveryJournal.ExpectedStaged.SHA256 != final.SHA256() ||
		manifest.RecoveryJournal.ExpectedFinal.Path != final.Path().String() ||
		manifest.RecoveryJournal.ExpectedFinal.SHA256 != final.SHA256() ||
		!validSHA256(manifest.RecoveryJournal.ValidatedCandidateSHA256) ||
		manifest.CompositeIdentity.Manifest.Path != snapshot.Manifest().Path().String() ||
		manifest.CompositeIdentity.LineageEdge.Path != snapshot.LineageEdge().Path().String() ||
		manifest.CompositeIdentity.LineageEdge.SHA256 != snapshot.LineageEdge().SHA256() ||
		manifest.CompositeIdentity.Epoch.Path != epoch.Record().Path().String() ||
		(normalExit != domain.ExitCommittedPass &&
			normalExit != domain.ExitCommittedCIRejected &&
			normalExit != domain.ExitIncompleteCoverage) {
		return PublicationDocument{}, PublicationDocument{}, fmt.Errorf("committed manifest recovery facts do not match snapshot")
	}

	restart := restartStateWire{
		SessionID:                run.SessionID().String(),
		RunID:                    run.RunID().String(),
		PersistedJournalState:    string(domain.JournalManifestCommitted),
		ExpectedStaged:           manifest.RecoveryJournal.ExpectedStaged,
		ExpectedFinal:            manifest.RecoveryJournal.ExpectedFinal,
		ValidatedCandidateSHA256: manifest.RecoveryJournal.ValidatedCandidateSHA256,
		StoreEpoch:               epoch.Value(),
		NormalExit:               manifest.ExitCode,
		ManifestPath:             snapshot.Manifest().Path().String(),
		LineageEdgePath:          snapshot.LineageEdge().Path().String(),
		EpochPath:                epoch.Record().Path().String(),
	}
	statusBytes, err := marshalCanonical(publicationStatusWire{
		SchemaVersion:        publicationStatusV1,
		PublicationStatus:    string(domain.PublicationCommitted),
		PublicationAuthority: string(domain.PublicationAuthorityP2),
		restartStateWire:     restart,
	})
	if err != nil {
		return PublicationDocument{}, PublicationDocument{}, err
	}
	status, err := mutableDocument(paths.status, statusBytes)
	if err != nil {
		return PublicationDocument{}, PublicationDocument{}, err
	}

	restart.PersistedJournalState = string(domain.JournalCompleted)
	journalBytes, err := marshalCanonical(publicationJournalWire{
		SchemaVersion:    publicationJournalV1,
		restartStateWire: restart,
	})
	if err != nil {
		return PublicationDocument{}, PublicationDocument{}, err
	}
	journal, err := mutableDocument(paths.journal, journalBytes)
	if err != nil {
		return PublicationDocument{}, PublicationDocument{}, err
	}
	return status, journal, nil
}

func (service *Service) observe(ctx context.Context, run ports.PublicationRun) (ports.PublicationObservation, domain.PublicationDecision, error) {
	if err := service.checkpoint(ctx, "publication.observe"); err != nil {
		return ports.PublicationObservation{}, domain.PublicationDecision{}, err
	}
	request, err := ports.NewObserveRunRequest(run, service.maxBytes)
	if err != nil {
		return ports.PublicationObservation{}, domain.PublicationDecision{}, publicationFailure("publication.observe", domain.FailureInternal, "observation request is invalid", err)
	}
	observation, err := service.store.ObserveRun(ctx, request)
	if err != nil {
		return ports.PublicationObservation{}, domain.PublicationDecision{}, service.storeFailure(ctx, "publication.observe", "publication observation failed", err)
	}
	if !observation.Valid() {
		return ports.PublicationObservation{}, domain.PublicationDecision{}, publicationFailure("publication.observe", domain.FailureArtifact, "store returned invalid observation", nil)
	}
	decision, err := domain.ClassifyPublication(observation.ClassifierInput())
	if err != nil {
		return ports.PublicationObservation{}, domain.PublicationDecision{}, publicationFailure("publication.observe", domain.FailureArtifact, "publication classification failed", err)
	}
	return observation, decision, nil
}

func (service *Service) writeDiagnostic(
	ctx context.Context,
	run ports.PublicationRun,
	observation ports.PublicationObservation,
	decision domain.PublicationDecision,
) error {
	epoch := observation.StoreEpoch()
	reasons := decision.Reasons()
	if !observation.Valid() ||
		!decision.Valid() ||
		decision.Status() != domain.PublicationCorrupt ||
		decision.Action() != domain.RecoveryActionEmitImmutableCorruptionDiagnostic ||
		epoch == 0 ||
		len(reasons) == 0 {
		return publicationFailure("recover.diagnostic", domain.FailureArtifact, "corruption observation is incomplete", nil)
	}
	observedDecision, err := domain.ClassifyPublication(observation.ClassifierInput())
	if err != nil || !reflect.DeepEqual(observedDecision, decision) {
		return publicationFailure("recover.diagnostic", domain.FailureArtifact, "corruption decision does not match the observation", err)
	}
	observationCAS, err := ports.NewCorruptionObservationCAS(observation)
	if err != nil {
		return publicationFailure("recover.diagnostic", domain.FailureArtifact, "corruption observation CAS is invalid", err)
	}
	if !reflect.DeepEqual(observationCAS.ReasonCodes(), reasons) {
		return publicationFailure("recover.diagnostic", domain.FailureArtifact, "corruption diagnostic reasons do not match the observation", nil)
	}
	wire := publicationCorruptionDiagnosticWire{
		SchemaVersion:    "mulgae-publication-corruption.v1",
		SessionID:        run.SessionID().String(),
		RunID:            run.RunID().String(),
		ObservationEpoch: epoch,
		ReasonCodes:      reasons,
	}
	bytes, err := marshalCanonical(wire)
	if err != nil {
		return publicationFailure("recover.diagnostic", domain.FailureInternal, "diagnostic serialization failed", err)
	}
	if len(bytes) == 0 || int64(len(bytes)) > service.maxBytes {
		return publicationFailure("recover.diagnostic", domain.FailureArtifact, "corruption diagnostic exceeds configured byte limit", nil)
	}
	path, err := ports.NewSafeRelativePath(fmt.Sprintf("%s/%s/recovery/diagnostics/publication-corrupt_%d.json", run.SessionID().String(), run.RunID().String(), epoch))
	if err != nil {
		return publicationFailure("recover.diagnostic", domain.FailureInternal, "diagnostic path is invalid", err)
	}
	diagnostic, err := ports.NewImmutablePublicationArtifact(path, sha256Identifier(bytes), bytes)
	if err != nil {
		return publicationFailure("recover.diagnostic", domain.FailureInternal, "diagnostic artifact is invalid", err)
	}
	request, err := ports.NewCorruptionDiagnosticRequest(run, observationCAS, diagnostic)
	if err != nil {
		return publicationFailure("recover.diagnostic", domain.FailureInternal, "diagnostic request is invalid", err)
	}
	if err := service.checkpoint(ctx, "recover.diagnostic"); err != nil {
		return err
	}
	result, writeErr := service.store.WriteCorruptionDiagnostic(ctx, request)
	if writeErr != nil {
		if result.Valid() || result.Durability().Valid() {
			cause := writeErr
			if result.Valid() && !diagnosticResultMatches(result, run, diagnostic) {
				cause = errors.Join(
					cause,
					publicationFailure("recover.diagnostic", domain.FailureArtifact, "store returned a mismatched diagnostic after write failure", nil),
				)
			}
			return errors.Join(errPublicationReobserve, cause)
		}
		return service.storeFailure(ctx, "recover.diagnostic", "corruption diagnostic write failed", writeErr)
	}
	if result.Durability() != ports.CorruptionDiagnosticDurable ||
		!diagnosticResultMatches(result, run, diagnostic) {
		return publicationFailure("recover.diagnostic", domain.FailureArtifact, "store returned inconsistent diagnostic receipt", nil)
	}
	return nil
}

type publicationCorruptionDiagnosticWire struct {
	SchemaVersion    string   `json:"schema_version"`
	SessionID        string   `json:"session_id"`
	RunID            string   `json:"run_id"`
	ObservationEpoch uint64   `json:"observation_epoch"`
	ReasonCodes      []string `json:"reason_codes"`
}

func journalForState(document PublicationDocument, state domain.PersistedJournalState) (PublicationDocument, error) {
	var wire publicationJournalWire
	if err := json.Unmarshal(document.Bytes(), &wire); err != nil {
		return PublicationDocument{}, fmt.Errorf("decode journal: %w", err)
	}
	wire.PersistedJournalState = string(state)
	bytes, err := marshalCanonical(wire)
	if err != nil {
		return PublicationDocument{}, fmt.Errorf("encode journal: %w", err)
	}
	return mutableDocument(document.Path(), bytes)
}

func observedJournalForState(document ports.ObservedMutablePublicationDocument, state domain.PersistedJournalState) (PublicationDocument, error) {
	if document.Document() != ports.MutablePublicationJournal {
		return PublicationDocument{}, fmt.Errorf("not a journal")
	}
	return journalForState(PublicationDocument{path: document.Path(), sha256: document.SHA256(), bytes: document.Bytes()}, state)
}

func issuedReviewIDFromMaterial(
	material ports.PublicationRecoveryMaterial,
	candidate ports.FinalReviewArtifact,
	prepared ports.PreparedComposite,
) (ports.IssuedReviewID, error) {
	var journal publicationJournalWire
	if err := unmarshalCanonicalPublicationRecord(material.Journal().Bytes(), &journal, "recovery journal"); err != nil {
		return ports.IssuedReviewID{}, err
	}
	if journal.SchemaVersion != publicationJournalV1 {
		return ports.IssuedReviewID{}, fmt.Errorf("recovery journal schema version is invalid")
	}
	var manifest runManifestWire
	if err := unmarshalCanonicalPublicationRecord(prepared.Composite().Manifest().Bytes(), &manifest, "recovery manifest"); err != nil {
		return ports.IssuedReviewID{}, err
	}
	if journal.ValidatedCandidateSHA256 == "" ||
		journal.ValidatedCandidateSHA256 != manifest.RecoveryJournal.ValidatedCandidateSHA256 {
		return ports.IssuedReviewID{}, fmt.Errorf("recovery material candidate binding does not match the immutable manifest")
	}
	return ports.NewIssuedReviewID(candidate.Identity().ReviewID(), journal.ValidatedCandidateSHA256)
}
func sameFinalArtifact(left, right ports.FinalReviewArtifact) bool {
	return left.Identity() == right.Identity() && bytes.Equal(left.Bytes(), right.Bytes())
}

func sameImmutableArtifact(left, right ports.ImmutablePublicationArtifact) bool {
	return left.Path() == right.Path() && left.SHA256() == right.SHA256() && bytes.Equal(left.Bytes(), right.Bytes())
}

func persistedCandidateMatches(
	result ports.PersistValidatedCandidateResult,
	run ports.PublicationRun,
	expected ports.FinalReviewArtifact,
) bool {
	return result.Valid() &&
		result.Receipt().Root() == run.Root() &&
		sameFinalArtifact(result.Candidate(), expected)
}

func persistedAuxiliaryMatches(
	result ports.PersistAuxiliaryArtifactResult,
	run ports.PublicationRun,
	expected ports.ImmutablePublicationArtifact,
) bool {
	return result.Valid() &&
		result.Receipt().Root() == run.Root() &&
		sameImmutableArtifact(result.Artifact(), expected)
}

func stagedFinalMatches(
	result ports.StageFinalResult,
	run ports.PublicationRun,
	expected ports.FinalReviewArtifact,
	stagedPath ports.SafeRelativePath,
) bool {
	return result.Valid() &&
		result.Final() == expected.Identity() &&
		result.StagedPath() == stagedPath &&
		result.Receipt().Root() == run.Root() &&
		result.Receipt().ByteLength() == int64(len(expected.Bytes()))
}

func installedFinalMatches(
	result ports.InstallFinalResult,
	run ports.PublicationRun,
	expected ports.FinalReviewArtifact,
) bool {
	return result.Valid() &&
		result.Final() == expected.Identity() &&
		result.Receipt().Root() == run.Root() &&
		result.Receipt().ByteLength() == int64(len(expected.Bytes()))
}

func mutableReplacementMatches(
	result ports.MutableReplaceResult,
	run ports.PublicationRun,
	request ports.MutableReplaceRequest,
) bool {
	return result.Valid() &&
		result.Document() == request.Document() &&
		result.Path() == request.Path() &&
		result.Receipt().Root() == run.Root() &&
		result.Receipt().SHA256() == request.SHA256() &&
		result.Receipt().ByteLength() == int64(len(request.Replacement()))
}

func diagnosticResultMatches(
	result ports.CorruptionDiagnosticResult,
	run ports.PublicationRun,
	expected ports.ImmutablePublicationArtifact,
) bool {
	return result.Valid() &&
		result.Receipt().Root() == run.Root() &&
		result.Receipt().ByteLength() == int64(len(expected.Bytes())) &&
		sameImmutableArtifact(result.Diagnostic(), expected)
}

func validatePublicationBundleSize(bundle PublicationBundle, maximum int64) error {
	if !bundle.Valid() || maximum <= 0 {
		return fmt.Errorf("invalid publication bundle or byte limit")
	}
	members := []struct {
		name  string
		bytes []byte
	}{
		{name: "final", bytes: bundle.Final().Bytes()},
		{name: "staged final", bytes: bundle.StagedFinal().Bytes()},
		{name: "manifest", bytes: bundle.Manifest().Bytes()},
		{name: "lineage edge", bytes: bundle.LineageEdge().Bytes()},
		{name: "epoch", bytes: bundle.Epoch().Record().Bytes()},
		{name: "journal", bytes: bundle.Journal().Bytes()},
		{name: "status", bytes: bundle.Status().Bytes()},
	}
	for index, excerpt := range bundle.Excerpts() {
		members = append(members, struct {
			name  string
			bytes []byte
		}{
			name:  fmt.Sprintf("excerpt %d", index+1),
			bytes: excerpt.Bytes(),
		})
	}
	for _, member := range members {
		if len(member.bytes) == 0 || int64(len(member.bytes)) > maximum {
			return fmt.Errorf("%s byte length %d exceeds limit %d", member.name, len(member.bytes), maximum)
		}
	}
	return nil
}

func sameCommitComposite(left, right ports.CommitCompositeRequest) bool {
	return left.Run() == right.Run() &&
		left.Final() == right.Final() &&
		sameImmutableArtifact(left.Manifest(), right.Manifest()) &&
		sameImmutableArtifact(left.LineageEdge(), right.LineageEdge()) &&
		left.Epoch().Value() == right.Epoch().Value() &&
		sameImmutableArtifact(left.Epoch().Record(), right.Epoch().Record())
}
func preparedMatchesComposite(prepared ports.PreparedComposite, composite ports.CommitCompositeRequest) bool {
	if !prepared.Valid() || !sameCommitComposite(prepared.Composite(), composite) {
		return false
	}
	for _, receipt := range prepared.Receipts() {
		if receipt.Root() != composite.Run().Root() {
			return false
		}
	}
	return true
}

func commitMatchesPreparedComposite(committed ports.CompositeCommitResult, prepared ports.PreparedComposite) bool {
	if !committed.Valid() || !prepared.Valid() {
		return false
	}
	expected := []ports.ImmutablePublicationArtifact{prepared.Composite().Manifest()}
	switch committed.Phase() {
	case ports.CompositeManifestInstalled:
	case ports.CompositeMembersInstalled:
		expected = append(expected, prepared.Composite().LineageEdge())
	default:
		expected = append(
			expected,
			prepared.Composite().LineageEdge(),
			prepared.Composite().Epoch().Record(),
		)
	}
	receipts := committed.Receipts()
	if len(receipts) != len(expected) {
		return false
	}
	for index, receipt := range receipts {
		if receipt.Root() != prepared.Composite().Run().Root() ||
			receipt.Destination() != expected[index].Path() ||
			receipt.SHA256() != expected[index].SHA256() ||
			receipt.ByteLength() != int64(len(expected[index].Bytes())) {
			return false
		}
	}
	return true
}

func validateRecoveryMaterial(
	run ports.PublicationRun,
	observation ports.PublicationObservation,
	material ports.PublicationRecoveryMaterial,
	candidate ports.FinalReviewArtifact,
	prepared ports.PreparedComposite,
) error {
	if !material.Valid() || !candidate.Valid() ||
		prepared.Durability() != ports.CompositePreparationDurable ||
		!preparedMatchesComposite(prepared, prepared.Composite()) ||
		prepared.Composite().Run() != run || prepared.Composite().Final() != candidate.Identity() {
		return fmt.Errorf("candidate or prepared composite does not match recovery run")
	}
	journal := material.Journal()
	expectedJournalPath, err := ports.NewSafeRelativePath(
		fmt.Sprintf("%s/%s/publication/journal.json", run.SessionID().String(), run.RunID().String()),
	)
	if err != nil {
		return err
	}
	if journal.Path() != expectedJournalPath {
		return fmt.Errorf("journal path is not canonical")
	}
	var wire publicationJournalWire
	if err := unmarshalCanonicalPublicationRecord(journal.Bytes(), &wire, "recovery journal"); err != nil {
		return err
	}
	if wire.SchemaVersion != publicationJournalV1 {
		return fmt.Errorf("recovery journal schema version is invalid")
	}
	normalExit, err := validatePublicationCompositeSemantics(
		candidate,
		prepared.Composite().Manifest(),
		prepared.Composite().LineageEdge(),
		prepared.Composite().Epoch(),
	)
	if err != nil {
		return fmt.Errorf("recovery immutable composite: %w", err)
	}
	if err := validateRestartStateSemantics(
		wire.restartStateWire,
		observation.ClassifierInput().JournalState(),
		normalExit,
		candidate.Identity(),
		prepared.Composite().Manifest(),
		prepared.Composite().LineageEdge(),
		prepared.Composite().Epoch(),
	); err != nil {
		return fmt.Errorf("recovery journal does not match durable material: %w", err)
	}
	if wire.StoreEpoch != observation.StoreEpoch() {
		return fmt.Errorf("recovery journal epoch does not match observation")
	}
	if _, err := ports.NewIssuedReviewID(candidate.Identity().ReviewID(), wire.ValidatedCandidateSHA256); err != nil {
		return fmt.Errorf("recovery journal candidate binding: %w", err)
	}
	expectedStaged, err := canonicalStagedFinalPath(run, candidate.Identity())
	if err != nil {
		return err
	}
	if stagedPath, ok := material.StagedPath(); ok && stagedPath != expectedStaged {
		return fmt.Errorf("staged path does not match recovery journal")
	}
	return nil
}

func expectationForDocument(document PublicationDocument) ports.MutableCASExpectation {
	expectation, err := ports.ExpectMutableSHA256(document.SHA256())
	if err != nil {
		panic(err)
	}
	return expectation
}

func expectationForObserved(document ports.ObservedMutablePublicationDocument) ports.MutableCASExpectation {
	if !document.Present() {
		return ports.ExpectMutableAbsent()
	}
	expectation, err := ports.ExpectMutableSHA256(document.SHA256())
	if err != nil {
		panic(err)
	}
	return expectation
}

func canonicalStagedFinalPath(run ports.PublicationRun, final ports.FinalReviewIdentity) (ports.SafeRelativePath, error) {
	return ports.NewSafeRelativePath(fmt.Sprintf("%s/%s/publication/staged/review_%s.json.tmp", run.SessionID().String(), run.RunID().String(), final.ReviewID().String()))
}

func mustInstallRequest(run ports.PublicationRun, staged ports.StageFinalResult) ports.InstallFinalRequest {
	request, err := ports.NewInstallFinalRequest(run, staged)
	if err != nil {
		panic(err)
	}
	return request
}

func reduceExit(code domain.OperationalExitCode, reason string) (domain.OperationalExitDecision, error) {
	exitReason, err := domain.NewExitReason(code, reason)
	if err != nil {
		return domain.OperationalExitDecision{}, err
	}
	return reduceExitReasons([]domain.ExitReason{exitReason})
}

func reduceExitReasons(reasons []domain.ExitReason) (domain.OperationalExitDecision, error) {
	input, err := domain.NewOperationalExitInput(reasons)
	if err != nil {
		return domain.OperationalExitDecision{}, err
	}
	return domain.ReduceOperationalExit(input)
}

func artifactExit(reasons []string) domain.OperationalExitDecision {
	reason := "publication_corrupt"
	if len(reasons) != 0 {
		reason = reasons[0]
	}
	exit, err := reduceExit(domain.ExitArtifactFailure, reason)
	if err != nil {
		panic(err)
	}
	return exit
}

type publicationFailureClassCarrier interface {
	PublicationFailureClass() domain.FailureClass
}

type publicationOperationalFailure struct {
	failure *domain.Failure
	exit    domain.OperationalExitDecision
}

func (failure *publicationOperationalFailure) Error() string {
	return failure.failure.Error()
}

func (failure *publicationOperationalFailure) Unwrap() error {
	return failure.failure
}

func (failure *publicationOperationalFailure) OperationalExit() domain.OperationalExitDecision {
	return failure.exit
}

func publicationExitFromError(err error) *domain.OperationalExitDecision {
	var failure *publicationOperationalFailure
	if !errors.As(err, &failure) {
		return nil
	}
	exit := failure.OperationalExit()
	return &exit
}

func combineExitDecisions(
	primary domain.OperationalExitDecision,
	additional *domain.OperationalExitDecision,
) domain.OperationalExitDecision {
	if additional == nil {
		return primary
	}
	reasons := append(primary.Reasons(), additional.Reasons()...)
	input, err := domain.NewOperationalExitInput(reasons)
	if err != nil {
		panic(err)
	}
	exit, err := domain.ReduceOperationalExit(input)
	if err != nil {
		panic(err)
	}
	return exit
}

func publicationFailureFromCause(
	ctx context.Context,
	stage string,
	fallback domain.FailureClass,
	reason string,
	cause error,
) error {
	cause = annotateFailure(stage, reason, cause)
	classes := publicationFailureClasses(cause)
	if len(classes) == 0 {
		classes = []domain.FailureClass{fallback}
	}
	reasons := make([]domain.ExitReason, 0, len(classes)+1)
	for _, class := range classes {
		reasons = append(reasons, publicationExitReason(class))
	}
	if ctx != nil && ctx.Err() != nil && !containsPublicationFailureClass(classes, domain.FailureCancelled) {
		reasons = append(reasons, publicationExitReason(domain.FailureCancelled))
		cause = errors.Join(cause, ctx.Err())
	}
	input, err := domain.NewOperationalExitInput(reasons)
	if err != nil {
		return publicationFailure(stage, domain.FailureInternal, "operational exit input is invalid", errors.Join(cause, err))
	}
	exit, err := domain.ReduceOperationalExit(input)
	if err != nil {
		return publicationFailure(stage, domain.FailureInternal, "operational exit reduction failed", errors.Join(cause, err))
	}
	failure, err := domain.NewFailure(stage, failureClassForExit(exit.Code()), reason, cause)
	if err != nil {
		return publicationFailure(stage, domain.FailureInternal, "operational failure construction failed", errors.Join(cause, err))
	}
	return &publicationOperationalFailure{failure: failure, exit: exit}
}

func publicationFailureClasses(cause error) []domain.FailureClass {
	classes := make([]domain.FailureClass, 0, 2)
	var visit func(error)
	visit = func(current error) {
		if current == nil {
			return
		}
		switch typed := current.(type) {
		case publicationFailureClassCarrier:
			if class := typed.PublicationFailureClass(); class.Valid() && !containsPublicationFailureClass(classes, class) {
				classes = append(classes, class)
			}
		case *domain.Failure:
			if class := typed.Class(); class.Valid() && !containsPublicationFailureClass(classes, class) {
				classes = append(classes, class)
			}
		}
		switch unwrapped := current.(type) {
		case interface{ Unwrap() []error }:
			for _, nested := range unwrapped.Unwrap() {
				visit(nested)
			}
			return
		case interface{ Unwrap() error }:
			visit(unwrapped.Unwrap())
			return
		}
		if errors.Is(current, context.Canceled) || errors.Is(current, context.DeadlineExceeded) {
			if !containsPublicationFailureClass(classes, domain.FailureCancelled) {
				classes = append(classes, domain.FailureCancelled)
			}
		}
	}
	visit(cause)
	return classes
}

func containsPublicationFailureClass(classes []domain.FailureClass, want domain.FailureClass) bool {
	for _, class := range classes {
		if class == want {
			return true
		}
	}
	return false
}

func publicationExitReason(class domain.FailureClass) domain.ExitReason {
	code := domain.ExitArtifactFailure
	reason := "publication_store_failure"
	switch class {
	case domain.FailureSecurityPolicy:
		code = domain.ExitSecurityViolation
		reason = "security_policy_violation"
	case domain.FailureConfiguration:
		code = domain.ExitConfiguration
		reason = "configuration_violation"
	case domain.FailureArtifact:
		reason = "artifact_failure"
	case domain.FailureInternal:
		code = domain.ExitInternalError
		reason = "mulgae_internal_error"
	case domain.FailureCancelled:
		code = domain.ExitCancelled
		reason = "user_cancelled"
	}
	exitReason, err := domain.NewExitReason(code, reason)
	if err != nil {
		panic(err)
	}
	return exitReason
}

func failureClassForExit(code domain.OperationalExitCode) domain.FailureClass {
	switch code {
	case domain.ExitInternalError:
		return domain.FailureInternal
	case domain.ExitArtifactFailure:
		return domain.FailureArtifact
	case domain.ExitSecurityViolation:
		return domain.FailureSecurityPolicy
	case domain.ExitCancelled:
		return domain.FailureCancelled
	case domain.ExitConfiguration:
		return domain.FailureConfiguration
	default:
		return domain.FailureInternal
	}
}

func (service *Service) ready(ctx context.Context, stage string) error {
	if service == nil || nilPublicationDependency(service.store) || nilPublicationDependency(service.validator) || nilPublicationDependency(service.clock) || service.maxBytes <= 0 {
		return publicationFailure(stage, domain.FailureInternal, "publication service is unavailable", nil)
	}
	return service.checkpoint(ctx, stage)
}
func (service *Service) checkpoint(ctx context.Context, stage string) error {
	if ctx == nil {
		return publicationFailure(stage, domain.FailureConfiguration, "context is required", nil)
	}
	if err := ctx.Err(); err != nil {
		return publicationFailure(stage, domain.FailureCancelled, "context cancelled", err)
	}
	return nil
}

func (service *Service) storeFailure(ctx context.Context, stage, reason string, cause error) error {
	return publicationFailureFromCause(ctx, stage, domain.FailureArtifact, reason, cause)
}

func (service *Service) classifyBuildFailure(ctx context.Context, cause error) error {
	return publicationFailureFromCause(
		ctx,
		"publish.build",
		domain.FailureArtifact,
		"publication bundle build failed",
		cause,
	)
}

func publicationFailure(stage string, class domain.FailureClass, reason string, cause error) error {
	cause = annotateFailure(stage, reason, cause)
	failure, err := domain.NewFailure(stage, class, reason, cause)
	if err != nil {
		return fmt.Errorf("publication failure construction: %w", err)
	}
	return failure
}

func nilPublicationDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
