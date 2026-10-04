package mcpentry

import (
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
)

func validateReviewGuard(input RunReviewInput, preflight bool) error {
	if input.ExpectedProjectBinding != nil {
		if _, err := domain.ParseProjectBinding(*input.ExpectedProjectBinding); err != nil {
			return reviewrun.ErrGuardInvalid
		}
	}
	return nil
}
