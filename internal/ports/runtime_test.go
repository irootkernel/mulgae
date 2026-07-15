package ports

import (
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

type fixedClock struct{ value time.Time }

func (clock fixedClock) Now() time.Time { return clock.value }

type fixedIDs struct{}

func (fixedIDs) NewSessionID(time.Time) (domain.SessionID, error) {
	return domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
}
func (fixedIDs) NewRunID(time.Time) (domain.RunID, error) {
	return domain.ParseRunID("r_019f596a-cf80-7c67-b265-f37053d51ccf")
}
func (fixedIDs) NewAttemptID(time.Time) (domain.AttemptID, error) {
	return domain.ParseAttemptID("a_019f596a-cf80-7c67-b265-f37053d51ccf")
}
func (fixedIDs) NewReviewID(time.Time) (domain.ReviewID, error) {
	return domain.ParseReviewID("019f596a-cf80-7c67-b265-f37053d51ccf")
}

type fixedSequence struct{ value uint64 }

func (sequence *fixedSequence) Next() (uint64, error) {
	sequence.value++
	return sequence.value, nil
}

var (
	_ Clock             = fixedClock{}
	_ IDGenerator       = fixedIDs{}
	_ SequenceGenerator = (*fixedSequence)(nil)
)

func TestRuntimePortsAreInjectableAndDeterministic(t *testing.T) {
	t.Parallel()

	now := time.Unix(1, 0).UTC()
	clock := fixedClock{value: now}
	if got := clock.Now(); got != now {
		t.Fatalf("clock = %v, want %v", got, now)
	}
	ids := fixedIDs{}
	session, err := ids.NewSessionID(clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if session.String() != "s_019f596a-cf80-7c67-b265-f37053d51ccf" {
		t.Fatalf("session ID = %q", session.String())
	}
	sequence := &fixedSequence{}
	first, err := sequence.Next()
	if err != nil {
		t.Fatal(err)
	}
	second, err := sequence.Next()
	if err != nil {
		t.Fatal(err)
	}
	if first != 1 || second != 2 {
		t.Fatalf("sequence = %d,%d", first, second)
	}
}
