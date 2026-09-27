package mcpentry

import (
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
)

func validateReviewGuard(input RunReviewInput, preflight bool) error {
	if preflight && input.ExpectedRequestDigest != nil {
		return reviewrun.ErrGuardIncomplete
	}
	if !preflight && (input.ExpectedProjectBinding == nil) != (input.ExpectedRequestDigest == nil) {
		return reviewrun.ErrGuardIncomplete
	}
	if input.ExpectedProjectBinding != nil {
		if _, err := domain.ParseProjectBinding(*input.ExpectedProjectBinding); err != nil {
			return reviewrun.ErrGuardInvalid
		}
	}
	if input.ExpectedRequestDigest != nil {
		if _, err := domain.ParseRequestIdentity(*input.ExpectedRequestDigest); err != nil {
			return reviewrun.ErrGuardInvalid
		}
	}
	return nil
}
