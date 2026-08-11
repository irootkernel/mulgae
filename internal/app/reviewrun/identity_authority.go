package reviewrun

import (
	"fmt"
	"sync"
	"time"

	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// runIdentityAuthority serializes the clock observation and UUIDv7 issuance
// across coordinator and provider worker goroutines. The caller-supplied time is
// intentionally ignored: observing it before acquiring this lock would allow
// concurrent calls to reach the monotonic generator in reverse clock order.
type runIdentityAuthority struct {
	mu    sync.Mutex
	clock ports.Clock
	ids   review.IdentityGenerator
}

func newRunIdentityAuthority(clock ports.Clock, ids review.IdentityGenerator) (*runIdentityAuthority, error) {
	if nilInterface(clock) || nilInterface(ids) {
		return nil, fmt.Errorf("review run: identity authority dependencies unavailable")
	}
	return &runIdentityAuthority{clock: clock, ids: ids}, nil
}

func (authority *runIdentityAuthority) nowLocked() (time.Time, error) {
	now := authority.clock.Now().UTC()
	if now.IsZero() {
		return time.Time{}, fmt.Errorf("review run: identity clock returned zero time")
	}
	return now, nil
}

func (authority *runIdentityAuthority) NewSessionID(time.Time) (domain.SessionID, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	now, err := authority.nowLocked()
	if err != nil {
		return domain.SessionID{}, err
	}
	return authority.ids.NewSessionID(now)
}

func (authority *runIdentityAuthority) NewRunID(time.Time) (domain.RunID, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	now, err := authority.nowLocked()
	if err != nil {
		return domain.RunID{}, err
	}
	return authority.ids.NewRunID(now)
}

func (authority *runIdentityAuthority) NewAttemptID(time.Time) (domain.AttemptID, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	now, err := authority.nowLocked()
	if err != nil {
		return domain.AttemptID{}, err
	}
	return authority.ids.NewAttemptID(now)
}

func (authority *runIdentityAuthority) NewRoleTaskID(time.Time) (string, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	now, err := authority.nowLocked()
	if err != nil {
		return "", err
	}
	return authority.ids.NewRoleTaskID(now)
}

func (authority *runIdentityAuthority) NewSourceInvocationID(time.Time) (string, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	now, err := authority.nowLocked()
	if err != nil {
		return "", err
	}
	return authority.ids.NewSourceInvocationID(now)
}

func (authority *runIdentityAuthority) NewExecutionInvocationID(time.Time) (string, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	now, err := authority.nowLocked()
	if err != nil {
		return "", err
	}
	return authority.ids.NewExecutionInvocationID(now)
}
