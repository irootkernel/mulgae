//go:build !darwin || !arm64

package filesystem

import (
	"context"
	"errors"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

var errPublicationStoreUnsupportedPlatform = errors.New("publication store requires darwin/arm64 secure filesystem primitives")

var _ ports.PublicationStore = (*PublicationStore)(nil)
var _ ports.PublicationEpochCommitStore = (*PublicationStore)(nil)

func (store *PublicationStore) IssueReviewID(context.Context, ports.IssueReviewIDRequest) (ports.IssuedReviewID, error) {
	return ports.IssuedReviewID{}, errPublicationStoreUnsupportedPlatform
}

func (store *PublicationStore) ResolveRun(context.Context, ports.ResolvePublicationRunRequest) (ports.PublicationRun, error) {
	return ports.PublicationRun{}, errPublicationStoreUnsupportedPlatform
}

func (store *PublicationStore) ObserveRun(context.Context, ports.ObserveRunRequest) (ports.PublicationObservation, error) {
	return ports.PublicationObservation{}, errPublicationStoreUnsupportedPlatform
}

func (store *PublicationStore) PersistValidatedCandidate(context.Context, ports.PersistValidatedCandidateRequest) (ports.PersistValidatedCandidateResult, error) {
	return ports.PersistValidatedCandidateResult{}, errPublicationStoreUnsupportedPlatform
}

func (store *PublicationStore) PersistAuxiliaryArtifact(context.Context, ports.PersistAuxiliaryArtifactRequest) (ports.PersistAuxiliaryArtifactResult, error) {
	return ports.PersistAuxiliaryArtifactResult{}, errPublicationStoreUnsupportedPlatform
}

func (store *PublicationStore) ReadAuxiliaryArtifact(context.Context, ports.ReadAuxiliaryArtifactRequest) (ports.ImmutablePublicationArtifact, error) {
	return ports.ImmutablePublicationArtifact{}, errPublicationStoreUnsupportedPlatform
}

func (store *PublicationStore) PrepareComposite(context.Context, ports.PrepareCompositeRequest) (ports.PreparedComposite, error) {
	return ports.PreparedComposite{}, errPublicationStoreUnsupportedPlatform
}

func (store *PublicationStore) StageFinal(context.Context, ports.StageFinalRequest) (ports.StageFinalResult, error) {
	return ports.StageFinalResult{}, errPublicationStoreUnsupportedPlatform
}

func (store *PublicationStore) AdoptStagedFinal(context.Context, ports.AdoptStagedFinalRequest) (ports.StageFinalResult, error) {
	return ports.StageFinalResult{}, errPublicationStoreUnsupportedPlatform
}

func (store *PublicationStore) InstallFinal(context.Context, ports.InstallFinalRequest) (ports.InstallFinalResult, error) {
	return ports.InstallFinalResult{}, errPublicationStoreUnsupportedPlatform
}

func (store *PublicationStore) ReplaceMutable(context.Context, ports.MutableReplaceRequest) (ports.MutableReplaceResult, error) {
	return ports.MutableReplaceResult{}, errPublicationStoreUnsupportedPlatform
}

func (store *PublicationStore) CommitPreparedComposite(context.Context, ports.PreparedComposite) (ports.CompositeCommitResult, error) {
	return ports.CompositeCommitResult{}, errPublicationStoreUnsupportedPlatform
}

func (store *PublicationStore) ReadCommittedSnapshot(context.Context, ports.ReadCommittedSnapshotRequest) (ports.CommittedPublicationSnapshot, error) {
	return ports.CommittedPublicationSnapshot{}, errPublicationStoreUnsupportedPlatform
}

func (store *PublicationStore) WriteCorruptionDiagnostic(context.Context, ports.CorruptionDiagnosticRequest) (ports.CorruptionDiagnosticResult, error) {
	return ports.CorruptionDiagnosticResult{}, errPublicationStoreUnsupportedPlatform
}
func (store *PublicationStore) WithNextPublicationEpoch(context.Context, ports.AnchoredRoot, func(context.Context, uint64) error) error {
	return errPublicationStoreUnsupportedPlatform
}
