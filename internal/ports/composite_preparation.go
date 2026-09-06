package ports

import "context"

// CompositePreparationStore exposes pre-journal material only for an exact
// composition replay. The application must compare a rebuilt candidate before
// adopting any member, and hold PublicationEpochCommitStore's root lock across
// inspection, adoption, and publication. These operations never replace bytes.
type CompositePreparationStore interface {
	ReadUnjournaledCompositeCandidate(context.Context, ObserveRunRequest) (FinalReviewArtifact, bool, error)
	// AdoptCompositePreparationArtifact returns true only after exact bytes and
	// filesystem identity have been verified and made durable; false means absent.
	AdoptCompositePreparationArtifact(context.Context, PublicationRun, ImmutablePublicationArtifact) (bool, error)
}
