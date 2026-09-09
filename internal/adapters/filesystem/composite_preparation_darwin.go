//go:build darwin && arm64

package filesystem

import (
	"context"
	"errors"
	"fmt"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

var _ ports.CompositePreparationStore = (*PublicationStore)(nil)

func (store *PublicationStore) ReadUnjournaledCompositeCandidate(ctx context.Context, request ports.ObserveRunRequest) (ports.FinalReviewArtifact, bool, error) {
	if ctx == nil || !request.Run().Valid() || request.MaxReadBytes() <= 0 {
		return ports.FinalReviewArtifact{}, false, errors.New("read composite preparation: invalid request")
	}
	if err := store.valid(); err != nil {
		return ports.FinalReviewArtifact{}, false, err
	}
	var result ports.FinalReviewArtifact
	err := store.withLock(ctx, request.Run().Root(), func() error {
		observation, _, err := store.observeLocked(ctx, request)
		if err != nil {
			return err
		}
		input := observation.ClassifierInput()
		if input.JournalState() != domain.JournalCollecting || input.Observation() != domain.DurableObservationP0None {
			return errors.New("read composite preparation: not an unjournaled candidate")
		}
		path, err := ports.ValidatedCandidatePath(request.Run())
		if err != nil {
			return err
		}
		file, err := readPublicationFile(request.Run().Root(), path, request.MaxReadBytes())
		if errors.Is(err, errPublicationAbsent) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := store.validatePublicationSchema(ctx, store.compositeFinalSchema, file.bytes); err != nil {
			return fmt.Errorf("read composite preparation: schema: %w", err)
		}
		facts, err := parsePublicationFinalFacts(file.bytes)
		if err != nil {
			return err
		}
		reviewID, err := domain.ParseReviewID(facts.reviewID)
		if err != nil {
			return err
		}
		finalPath, err := ports.NewSafeRelativePath(request.Run().SessionID().String() + "/" + request.Run().RunID().String() + "/review_" + reviewID.String() + ".json")
		if err != nil {
			return err
		}
		identity, err := ports.NewFinalReviewIdentity(reviewID, finalPath, file.sha256)
		if err != nil {
			return err
		}
		result, err = ports.NewFinalReviewArtifact(identity, file.bytes)
		return err
	})
	if err != nil {
		return ports.FinalReviewArtifact{}, false, err
	}
	return result, result.Valid(), nil
}

func (store *PublicationStore) AdoptCompositePreparationArtifact(ctx context.Context, run ports.PublicationRun, artifact ports.ImmutablePublicationArtifact) (bool, error) {
	if ctx == nil || !run.Valid() || !artifact.Valid() {
		return false, errors.New("adopt composite preparation: invalid request")
	}
	if err := store.valid(); err != nil {
		return false, err
	}
	candidatePath, err := ports.ValidatedCandidatePath(run)
	if err != nil {
		return false, err
	}
	channel := "publication_auxiliary_artifact"
	if artifact.Path() == candidatePath {
		channel = "publication_validated_candidate"
		if err := store.validatePublicationSchema(ctx, store.compositeFinalSchema, artifact.Bytes()); err != nil {
			return false, err
		}
	} else if _, err := ports.NewPersistRunSupportArtifactRequest(run, artifact); err != nil {
		return false, err
	}
	var exists bool
	err = store.withLock(ctx, run.Root(), func() error {
		_, found, err := store.durableExistingImmutable(run, artifact, channel)
		exists = found
		return err
	})
	return exists && err == nil, err
}
