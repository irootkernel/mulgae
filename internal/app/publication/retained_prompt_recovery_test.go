package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"github.com/irootkernel/mulgae/internal/testsupport/historical"
)

func retainedFrozenPromptFixture(t *testing.T) (publicationServiceFixture, domain.AttemptID) {
	t.Helper()
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range corpus.Cases {
		if c.ID != "ordinary-v2" {
			continue
		}
		run, snapshot := retainedHistoricalSnapshot(t, c)
		status, journal, err := completedRecoveryDocuments(run, snapshot)
		if err != nil {
			t.Fatal(err)
		}
		var manifest runManifestWire
		if err := json.Unmarshal(snapshot.Manifest().Bytes(), &manifest); err != nil {
			t.Fatal(err)
		}
		staged, err := immutableArtifact(mustPublicationPath(manifest.RecoveryJournal.ExpectedStaged.Path), snapshot.Final().Bytes())
		if err != nil {
			t.Fatal(err)
		}
		files := c.Artifacts()
		indexPath := manifest.CompositeIdentity.SupportIndex.Path
		var index runSupportIndexWire
		if err := json.Unmarshal(files[indexPath], &index); err != nil {
			t.Fatal(err)
		}
		var support []ports.ImmutablePublicationArtifact
		for _, member := range append(index.Artifacts, artifactIdentityWire{Path: indexPath}) {
			a, err := immutableArtifact(mustPublicationPath(member.Path), files[member.Path])
			if err != nil {
				t.Fatal(err)
			}
			support = append(support, a)
		}
		bundle := PublicationBundle{final: snapshot.Final(), manifest: snapshot.Manifest(), lineageEdge: snapshot.LineageEdge(), epoch: snapshot.Epoch(), staged: staged, status: status, journal: journal, excerpts: support}
		issued, err := ports.NewIssuedReviewID(snapshot.Final().Identity().ReviewID(), manifest.RecoveryJournal.ValidatedCandidateSHA256)
		if err != nil {
			t.Fatal(err)
		}
		attempt, err := domain.ParseAttemptID(c.Attempts[0].AttemptID)
		if err != nil {
			t.Fatal(err)
		}
		return publicationServiceFixture{root: run.Root(), run: run, issued: issued, bundle: bundle}, attempt
	}
	t.Fatal("fixed prompt source absent")
	return publicationServiceFixture{}, domain.AttemptID{}
}

func TestRecoverFrozenPromptSupportRetainsIdentityAndDefensiveGetters(t *testing.T) {
	fixture, attemptID := retainedFrozenPromptFixture(t)
	store := newPublicationServiceHappyStore(t, fixture)
	store.issue = func(ports.IssueReviewIDRequest) (ports.IssuedReviewID, error) {
		t.Fatal("frozen recovery tried to issue an ID")
		return ports.IssuedReviewID{}, nil
	}
	service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Recover(context.Background(), fixture.run)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := result.PromptManifestArtifact(attemptID, 1)
	if !ok {
		t.Fatal("recovered P2 omitted verified prompt identity")
	}
	var expected ports.ImmutablePublicationArtifact
	for _, a := range fixture.bundle.SupportArtifacts() {
		identity := runSupportArtifactIdentity(a)
		id, seq, present := identity.promptManifestBinding()
		if present && id == attemptID && seq == 1 {
			expected = a
		}
	}
	if !expected.Valid() || got.Path() != expected.Path() || got.SHA256() != expected.SHA256() {
		t.Fatal("prompt identity differs from fixed re-read bytes")
	}
	identities := result.PersistedRunSupportArtifacts()
	if len(identities) == 0 {
		t.Fatal("verified support omitted")
	}
	identities[0] = RunSupportArtifactIdentity{}
	if _, ok := result.PromptManifestArtifact(attemptID, 1); !ok {
		t.Fatal("support getter aliases result")
	}
	final, err := ports.NewImmutablePublicationArtifact(fixture.bundle.Final().Identity().Path(), fixture.bundle.Final().Identity().SHA256(), fixture.bundle.Final().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range [][]RunSupportArtifactIdentity{{runSupportArtifactIdentity(final)}, nil, {got, got}} {
		result.supportArtifacts = wrong
		if _, ok := result.PromptManifestArtifact(attemptID, 1); ok {
			t.Fatal("wrong-kind, missing or ambiguous prompt identity accepted")
		}
	}
}

// The observations advance only when the corresponding store effect succeeds.
// This is the retained recovery consumer, not a replay/captured writer.
func retainedPromptEffectStore(t *testing.T, fixture publicationServiceFixture, boundary string) (*publicationServiceScriptedStore, *bool, *int) {
	t.Helper()
	store := newPublicationServiceHappyStore(t, fixture)
	prepared := publicationServicePreparedComposite(t, fixture.root, fixture.run, fixture.bundle)
	installed, committed := boundary != "final install", boundary == "status replacement"
	state := domain.JournalFinalStaged
	if boundary == "composite commit" {
		state = domain.JournalFinalFileInstalled
	}
	if committed {
		state = domain.JournalCompleted
	}
	journal := publicationServiceJournalForState(t, fixture.bundle.Journal(), state)
	status := fixture.bundle.Status()
	statusBytes := []byte("{")
	armed, injections := false, 0
	inject := func(selected string) error {
		if selected != boundary {
			return nil
		}
		armed = true
		injections++
		return errors.New(selected + " completion uncertain")
	}
	baseInstall := store.install
	store.install = func(request ports.InstallFinalRequest) (ports.InstallFinalResult, error) {
		if installed || committed || request.Run() != fixture.run || request.Staged().Final() != fixture.bundle.Final().Identity() || request.Staged().StagedPath() != fixture.bundle.StagedFinal().Path() {
			t.Fatal("install reached with wrong state/material")
		}
		result, err := baseInstall(request)
		if err != nil || !result.Valid() {
			t.Fatalf("install positive effect: %v", err)
		}
		installed = true
		return result, inject("final install")
	}
	baseCommit := store.commit
	store.commit = func(actual ports.PreparedComposite) (ports.CompositeCommitResult, error) {
		if !installed || committed || !reflect.DeepEqual(actual, prepared) {
			t.Fatal("commit reached with wrong state/material")
		}
		result, err := baseCommit(actual)
		if err != nil || !result.Valid() {
			t.Fatalf("commit positive effect: %v", err)
		}
		committed = true
		return result, inject("composite commit")
	}
	baseReplace := store.replace
	store.replace = func(request ports.MutableReplaceRequest) (ports.MutableReplaceResult, error) {
		if !committed || request.Run() != fixture.run {
			t.Fatal("mutable replacement preceded P2")
		}
		result, err := baseReplace(request)
		if err != nil || !result.Valid() {
			t.Fatalf("mutable positive effect: %v", err)
		}
		if request.Document() == ports.MutablePublicationStatus {
			if request.Path() != status.Path() || !bytes.Equal(request.Replacement(), status.Bytes()) {
				t.Fatal("status replacement changed frozen bytes")
			}
			prior, err := ports.ExpectMutableSHA256(sha256Identifier(statusBytes))
			if err != nil || !reflect.DeepEqual(request.ExpectedPrior(), prior) {
				t.Fatal("status CAS did not bind observed material")
			}
			statusBytes = request.Replacement()
			return result, inject("status replacement")
		}
		prior, err := ports.ExpectMutableSHA256(journal.SHA256())
		if err != nil || !reflect.DeepEqual(request.ExpectedPrior(), prior) {
			t.Fatal("journal CAS did not bind observed material")
		}
		next := fixture.bundle.Journal()
		intermediate := publicationServiceJournalForState(t, fixture.bundle.Journal(), domain.JournalManifestCommitted)
		if bytes.Equal(request.Replacement(), intermediate.Bytes()) {
			next = intermediate
		}
		if request.Path() != next.Path() || !bytes.Equal(request.Replacement(), next.Bytes()) {
			t.Fatal("journal replacement changed frozen bytes")
		}
		journal = next
		return result, nil
	}
	store.issue = func(ports.IssueReviewIDRequest) (ports.IssuedReviewID, error) {
		t.Fatal("recovery issued a new identity")
		return ports.IssuedReviewID{}, nil
	}
	store.observe = func() (ports.PublicationObservation, error) {
		if !committed {
			var staged *ports.SafeRelativePath
			class := domain.DurableObservationP1Installed
			if !installed {
				path := fixture.bundle.StagedFinal().Path()
				staged = &path
				class = domain.DurableObservationP0Staged
			}
			material := publicationServiceRecoveryMaterial(t, fixture.bundle, journal, staged, prepared)
			return publicationServiceObservationWithMaterial(t, state, class, fixture.bundle.Epoch().Value(), material), nil
		}
		observedJournal, err := ports.NewObservedMutablePublicationDocument(ports.MutablePublicationJournal, journal.Path(), journal.SHA256(), journal.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		observedStatus, err := ports.NewObservedMutablePublicationDocument(ports.MutablePublicationStatus, status.Path(), sha256Identifier(statusBytes), statusBytes)
		if err != nil {
			t.Fatal(err)
		}
		material, err := ports.NewPublicationRecoveryMaterialWithCommittedSnapshot(fixture.bundle.Final(), observedJournal, observedStatus, publicationServiceSnapshot(t, fixture.bundle))
		if err != nil {
			t.Fatal(err)
		}
		// The classifier observes the journal state that was actually written.
		var wire publicationJournalWire
		if err := json.Unmarshal(journal.Bytes(), &wire); err != nil {
			t.Fatal(err)
		}
		return publicationServiceP2Observation(t, domain.PersistedJournalState(wire.PersistedJournalState), domain.ExitCommittedCIRejected, fixture.bundle.Epoch().Value(), material), nil
	}
	return store, &armed, &injections
}

func TestRecoverFrozenPromptSupportSurvivesPostEffectUncertainty(t *testing.T) {
	for _, boundary := range []string{"final install", "composite commit", "status replacement"} {
		t.Run(boundary, func(t *testing.T) {
			fixture, attemptID := retainedFrozenPromptFixture(t)
			store, armed, injections := retainedPromptEffectStore(t, fixture, boundary)
			service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.Recover(context.Background(), fixture.run)
			if err != nil || result.Decision().Authority() != domain.PublicationAuthorityP2 {
				t.Fatalf("post-effect recovery lost P2: %v", err)
			}
			if !*armed || *injections != 1 {
				t.Fatal("selected error/effect did not execute exactly once")
			}
			got, ok := result.PromptManifestArtifact(attemptID, 1)
			if !ok {
				t.Fatal("post-effect recovery lost verified prompt identity")
			}
			matched := false
			for _, expected := range fixture.bundle.SupportArtifacts() {
				if expected.Path() == got.Path() {
					matched = expected.SHA256() == got.SHA256()
				}
			}
			if !matched || len(result.PersistedRunSupportArtifacts()) != len(fixture.bundle.SupportArtifacts()) || len(store.issueRequests) != 0 {
				t.Fatal("recovery changed persisted identity or support count")
			}
			var actions []string
			for _, call := range store.calls {
				if call != "read_auxiliary" {
					actions = append(actions, call)
				}
			}
			want := map[string][]string{
				"final install":      {"observe", "adopt", "install", "observe", "commit", "journal", "observe", "status", "journal", "observe"},
				"composite commit":   {"observe", "commit", "observe", "status", "journal", "observe"},
				"status replacement": {"observe", "status", "observe"},
			}[boundary]
			if !reflect.DeepEqual(actions, want) {
				t.Fatalf("effect order = %#v, want %#v", actions, want)
			}
		})
	}
}

func TestRecoverFrozenPostEffectP2RefusesEveryUnreadableSupportCombination(t *testing.T) {
	for _, boundary := range []string{"final install", "composite commit", "status replacement"} {
		for _, failure := range []string{"missing support index", "corrupt support index", "missing selected prompt", "corrupt selected prompt"} {
			t.Run(boundary+"/"+failure, func(t *testing.T) {
				fixture, _ := retainedFrozenPromptFixture(t)
				store, armed, injections := retainedPromptEffectStore(t, fixture, boundary)
				baseRead := store.readAuxiliary
				failedReads := 0
				store.readAuxiliary = func(request ports.ReadAuxiliaryArtifactRequest) (ports.ImmutablePublicationArtifact, error) {
					selected := request.Kind() == ports.RunSupportArtifactPromptManifest
					if strings.HasSuffix(failure, "support index") {
						selected = request.Kind() == ports.RunSupportArtifactSupportIndex
					}
					if *armed && selected {
						failedReads++
						if strings.HasPrefix(failure, "missing") {
							return ports.ImmutablePublicationArtifact{}, fs.ErrNotExist
						}
						return ports.ImmutablePublicationArtifact{}, nil
					}
					return baseRead(request)
				}
				service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
				if err != nil {
					t.Fatal(err)
				}
				result, err := service.Recover(context.Background(), fixture.run)
				publicationServiceRequireFailureClass(t, err, domain.FailureArtifact)
				if !*armed || *injections != 1 || failedReads != 1 {
					t.Fatalf("effect/refusal not reached: injected=%d failedReads=%d", *injections, failedReads)
				}
				if _, ok := result.Snapshot(); !ok {
					t.Fatal("support failure discarded committed snapshot")
				}
				if result.Decision().Authority() != domain.PublicationAuthorityP2 || result.Decision().Status() != domain.PublicationCommitted {
					t.Fatal("support failure downgraded durable authority")
				}
				if len(store.issueRequests) != 0 {
					t.Fatal("recovery issued fresh identity")
				}
			})
		}
	}
}

func TestRecoverFrozenCompletedJournalRefusesUnreadableBoundSupport(t *testing.T) {
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
			fixture, _ := retainedFrozenPromptFixture(t)
			store := newPublicationServiceHappyStore(t, fixture)
			baseRead := store.readAuxiliary
			store.readAuxiliary = func(request ports.ReadAuxiliaryArtifactRequest) (ports.ImmutablePublicationArtifact, error) {
				if failure.match(request) {
					return failure.read()
				}
				return baseRead(request)
			}
			service, err := NewService(store, retainedSchema(t), publicationServiceClock{now: publicationTestTime()}, publicationServiceTestMaxBytes)
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
