package rerun

import "github.com/irootkernel/mulgae/internal/domain"

func (source SourceAttempt) Reference() (domain.SourceReference, error) {
	if source.RecoveryManifestSHA256 != "" {
		if source.ReviewID.String() != "" {
			return domain.SourceReference{}, ErrSourceCorrupt
		}
		return domain.NewRecoverySourceReference(source.RunID, source.RecoveryManifestSHA256)
	}
	return domain.NewPublishedSourceReference(source.RunID, source.ReviewID)
}
