package domain

import (
	"fmt"
	"time"
)

type Session struct {
	id        SessionID
	createdAt time.Time
	rootRunID RunID
}

func NewReviewSession(sessionID SessionID, createdAt time.Time, runID RunID, target TargetIdentity, roles []RoleTask) (Session, Run, error) {
	if _, err := ParseSessionID(sessionID.String()); err != nil {
		return Session{}, Run{}, fmt.Errorf("review session: %w: invalid session ID: %v", ErrInvariant, err)
	}
	if createdAt.IsZero() || createdAt.Location() != time.UTC {
		return Session{}, Run{}, fmt.Errorf("review session: %w: created_at must be non-zero UTC", ErrInvariant)
	}
	run, err := newRun(runID, sessionID, RunTypeReview, target, roles)
	if err != nil {
		return Session{}, Run{}, err
	}
	return Session{id: sessionID, createdAt: createdAt, rootRunID: run.ID()}, run, nil
}

func (session Session) ID() SessionID        { return session.id }
func (session Session) CreatedAt() time.Time { return session.createdAt }
func (session Session) RootRunID() RunID     { return session.rootRunID }
