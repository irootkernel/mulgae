package publication

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestRetainedLiveRecoverP0NoneHasNoTerminalExit(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
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
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
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
func TestRetainedLiveP2ResultRejectsIssuedCandidateBindingMismatch(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
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
func TestRetainedLivePublishRecoveredRejectsIssuedCandidateBindingMismatch(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
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
	if !publicationServiceCallsEqual(store.calls, publicationServiceObserveReadCalls(fixture, "observe")) {
		t.Fatalf("recovery binding mismatch calls = %#v", store.calls)
	}
}

func TestRetainedLiveRecoverP2ReconstructionErrorOverridesStoredNormalExit(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
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
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	result, recoverErr := service.Recover(context.Background(), fixture.run)
	publicationServiceRequireFailureClass(t, recoverErr, domain.FailureArtifact)
	exit := result.Exit()
	if exit == nil || exit.Code() != domain.ExitArtifactFailure {
		t.Fatalf("errored P2 recovery exit = %#v, want artifact exit 7", exit)
	}
	if !publicationServiceCallsEqual(store.calls, []string{
		"observe", "read_auxiliary", "read_auxiliary", "read_auxiliary", "read_auxiliary", "status",
	}) {
		t.Fatalf("errored P2 recovery calls = %#v", store.calls)
	}
}

func TestRetainedLiveP2ResultRejectsSnapshotWarningsOutsidePolicy(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
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
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.p2Result(context.Background(), fixture.run, nil, nil, nil)
	publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
	if !publicationServiceCallsEqual(store.calls, []string{"observe"}) {
		t.Fatalf("semantic snapshot rejection calls = %#v", store.calls)
	}
}

func TestRetainedLiveRecoverForwardsExactCorruptionObservationCASFacts(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
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
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
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

func TestRetainedLiveRecoverRejectsCorruptionDiagnosticOverConfiguredByteLimit(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
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
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, 1)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Recover(context.Background(), fixture.run)
	publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
	if !publicationServiceCallsEqual(store.calls, []string{"observe"}) {
		t.Fatalf("oversize diagnostic calls = %#v", store.calls)
	}
}

func TestRetainedLiveRecoverAdoptsDurableStagedFinalBeforeInstall(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
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
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, int64(len(fixture.bundle.Final().Bytes())))
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

func TestRetainedLiveRecoverCommitsExactPreparedCompositeFromP1Installed(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
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
		retainedSchema(t),
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
		!publicationServiceCallsEqual(store.calls, []string{
			"observe", "commit", "journal", "observe",
			"read_auxiliary", "read_auxiliary", "read_auxiliary", "read_auxiliary",
		}) {
		t.Fatalf("P1 recovery = authority %q, commit calls %d, calls %#v", result.Decision().Authority(), commitCalls, store.calls)
	}
}

func TestRetainedLiveRecoverReobservesValidAdoptionPostEffectResult(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
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
		retainedSchema(t),
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
	want := []string{
		"observe", "adopt", "observe", "adopt", "install", "observe",
		"read_auxiliary", "read_auxiliary", "read_auxiliary", "read_auxiliary",
	}
	if !publicationServiceCallsEqual(store.calls, want) {
		t.Fatalf("calls = %#v, want %#v", store.calls, want)
	}
}
func TestRetainedLiveRecoverRejectsMismatchedPreIDCandidateBinding(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
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
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Recover(context.Background(), fixture.run)
	publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
	if !publicationServiceCallsEqual(store.calls, []string{"observe"}) {
		t.Fatalf("recovery calls = %#v, want only observation before mismatch rejection", store.calls)
	}
}

func TestRetainedLiveRecoverNamedCrossBoundaryCorruptionOnlyWritesDiagnostic(t *testing.T) {
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
			fixture := retainedLiveServiceFixture(t)
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
			service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
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
func TestRetainedLiveRecoverCorruptionDiagnosticIsIdempotentByEpochAndBytes(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
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
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
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

func TestRetainedLiveRecoverReobservesValidDiagnosticPostEffectResult(t *testing.T) {
	t.Parallel()

	fixture := retainedLiveServiceFixture(t)
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
		retainedSchema(t),
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
