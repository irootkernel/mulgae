package ports

import (
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
)

// Clock is the only source of wall-clock time used by application services.
type Clock interface {
	Now() time.Time
}

// IDGenerator creates canonical UUIDv7 identifiers from an injected timestamp.
// Implementations must surface clock regression rather than silently hiding it.
type IDGenerator interface {
	NewSessionID(now time.Time) (domain.SessionID, error)
	NewRunID(now time.Time) (domain.RunID, error)
	NewAttemptID(now time.Time) (domain.AttemptID, error)
	NewReviewID(now time.Time) (domain.ReviewID, error)
}

// InvocationIdentityGenerator creates provider invocation identity through the
// same monotonic UUIDv7 issuance path as other runtime identifiers.
type InvocationIdentityGenerator interface {
	NewRoleTaskID(now time.Time) (string, error)
	NewSourceInvocationID(now time.Time) (string, error)
	NewExecutionInvocationID(now time.Time) (string, error)
}

// SequenceGenerator supplies exact coordinator program order independently of
// approximate UUID or wall-clock ordering.
type SequenceGenerator interface {
	Next() (uint64, error)
}
