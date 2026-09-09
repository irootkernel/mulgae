package publication

import (
	"fmt"

	"github.com/irootkernel/mulgae/internal/domain"
)

func compositeReference(run domain.RunID, review domain.ReviewID, hash string) (domain.SourceReference, error) {
	if hash != "" {
		if review.String() != "" {
			return domain.SourceReference{}, fmt.Errorf("ambiguous composite source")
		}
		return domain.NewRecoverySourceReference(run, hash)
	}
	return domain.NewPublishedSourceReference(run, review)
}
func compositeFingerprint(root domain.SourceReference, sources []domain.CompositionSource) (domain.CompositionFingerprint, error) {
	if root.Kind() == "failed_run_recovery" {
		return domain.NewRecoveryCompositionFingerprint(root, sources)
	}
	return domain.NewCompositionFingerprint(root.RunID(), sources)
}
func compositeSourceKind(rootHash, sourceHash string) string {
	if rootHash == "" {
		return ""
	}
	if sourceHash != "" {
		return "failed_run_recovery"
	}
	return "published_review"
}
