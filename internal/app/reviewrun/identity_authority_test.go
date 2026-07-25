package reviewrun

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

type runIdentityTestClock struct{ sequence atomic.Int64 }

func (clock *runIdentityTestClock) Now() time.Time {
	return time.Date(2026, 7, 24, 12, 0, 0, int(clock.sequence.Add(1)), time.UTC)
}

type runIdentityTestIDs struct {
	active     atomic.Int32
	concurrent atomic.Bool
	mu         sync.Mutex
	times      []time.Time
}

func (ids *runIdentityTestIDs) record(now time.Time) {
	if ids.active.Add(1) != 1 {
		ids.concurrent.Store(true)
	}
	time.Sleep(time.Millisecond)
	ids.mu.Lock()
	ids.times = append(ids.times, now)
	ids.mu.Unlock()
	ids.active.Add(-1)
}

func (ids *runIdentityTestIDs) NewSessionID(now time.Time) (domain.SessionID, error) {
	ids.record(now)
	return domain.ParseSessionID("s_019f5a09-5eec-7001-8001-000000000001")
}
func (ids *runIdentityTestIDs) NewRunID(now time.Time) (domain.RunID, error) {
	ids.record(now)
	return domain.ParseRunID("r_019f5a09-5eec-7001-8001-000000000002")
}
func (ids *runIdentityTestIDs) NewAttemptID(now time.Time) (domain.AttemptID, error) {
	ids.record(now)
	return domain.ParseAttemptID("a_019f5a09-5eec-7001-8001-000000000003")
}
func (ids *runIdentityTestIDs) NewRoleTaskID(now time.Time) (string, error) {
	ids.record(now)
	return "rt_019f5a09-5eec-7001-8001-000000000004", nil
}
func (ids *runIdentityTestIDs) NewSourceInvocationID(now time.Time) (string, error) {
	ids.record(now)
	return "i_019f5a09-5eec-7001-8001-000000000005", nil
}
func (ids *runIdentityTestIDs) NewExecutionInvocationID(now time.Time) (string, error) {
	ids.record(now)
	return "019f5a09-5eec-7001-8001-000000000006", nil
}

func TestRunIdentityAuthoritySerializesClockAndIssuance(t *testing.T) {
	clock := &runIdentityTestClock{}
	ids := &runIdentityTestIDs{}
	authority, err := newRunIdentityAuthority(clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	const calls = 24
	var group sync.WaitGroup
	for index := 0; index < calls; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := authority.NewSourceInvocationID(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
				t.Errorf("NewSourceInvocationID() error = %v", err)
			}
		}()
	}
	group.Wait()
	if ids.concurrent.Load() {
		t.Fatal("underlying identity generator was entered concurrently")
	}
	if len(ids.times) != calls {
		t.Fatalf("issued timestamps = %d, want %d", len(ids.times), calls)
	}
	for index := 1; index < len(ids.times); index++ {
		if !ids.times[index].After(ids.times[index-1]) {
			t.Fatalf("timestamps were not issued in order: %v", ids.times)
		}
	}
}
