package runtime

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUUIDv7GeneratorCreatesCanonicalTypedIdentifiers(t *testing.T) {
	generator := &UUIDv7Generator{entropy: bytes.NewReader(bytes.Repeat([]byte{0xab}, 50))}
	now := time.Date(2026, 7, 14, 12, 0, 0, 123_000_000, time.FixedZone("offset", 3600))

	session, err := generator.NewSessionID(now)
	if err != nil {
		t.Fatal(err)
	}
	run, err := generator.NewRunID(now)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := generator.NewAttemptID(now)
	if err != nil {
		t.Fatal(err)
	}
	review, err := generator.NewReviewID(now)
	if err != nil {
		t.Fatal(err)
	}
	request, err := generator.NewRequestID(now)
	if err != nil {
		t.Fatal(err)
	}

	for name, value := range map[string]string{
		"session": session.String(),
		"run":     run.String(),
		"attempt": attempt.String(),
		"review":  review.String(),
		"request": request,
	} {
		identifier := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(value, "s_"), "r_"), "a_"), "i_")
		if len(identifier) != 36 || identifier[14] != '7' || !strings.Contains("89ab", string(identifier[19])) {
			t.Fatalf("%s identifier = %q, want canonical UUIDv7", name, value)
		}
	}
}

func TestUUIDv7GeneratorCreatesCanonicalInvocationIdentifiers(t *testing.T) {
	generator := &UUIDv7Generator{entropy: bytes.NewReader(bytes.Repeat([]byte{0xab}, 30))}
	now := time.Date(2026, 7, 14, 12, 0, 0, 123_000_000, time.FixedZone("offset", 3600))

	roleTaskID, err := generator.NewRoleTaskID(now)
	if err != nil {
		t.Fatal(err)
	}
	sourceInvocationID, err := generator.NewSourceInvocationID(now)
	if err != nil {
		t.Fatal(err)
	}
	executionInvocationID, err := generator.NewExecutionInvocationID(now)
	if err != nil {
		t.Fatal(err)
	}

	for _, identifier := range []struct {
		name   string
		value  string
		prefix string
	}{
		{name: "role task", value: roleTaskID, prefix: "rt_"},
		{name: "source invocation", value: sourceInvocationID, prefix: "i_"},
		{name: "execution invocation", value: executionInvocationID, prefix: ""},
	} {
		if !strings.HasPrefix(identifier.value, identifier.prefix) {
			t.Fatalf("%s identifier = %q, want prefix %q", identifier.name, identifier.value, identifier.prefix)
		}
		raw := strings.TrimPrefix(identifier.value, identifier.prefix)
		if len(raw) != 36 || raw[14] != '7' || !strings.Contains("89ab", string(raw[19])) {
			t.Fatalf("%s identifier = %q, want canonical UUIDv7", identifier.name, identifier.value)
		}
	}
}
func TestUUIDv7GeneratorRejectsRegressionAndEntropyFailure(t *testing.T) {
	generator := &UUIDv7Generator{entropy: bytes.NewReader(bytes.Repeat([]byte{1}, 20))}
	now := time.UnixMilli(2_000)
	if _, err := generator.NewRequestID(now); err != nil {
		t.Fatal(err)
	}
	if _, err := generator.NewRequestID(now.Add(-time.Millisecond)); !errors.Is(err, ErrClockRegression) {
		t.Fatalf("regression error = %v, want %v", err, ErrClockRegression)
	}

	failed := &UUIDv7Generator{entropy: bytes.NewReader(nil)}
	if _, err := failed.NewRequestID(now); err == nil {
		t.Fatal("entropy exhaustion succeeded")
	}
	if _, err := failed.NewRequestID(time.Time{}); err == nil {
		t.Fatal("zero time succeeded")
	}
}
func TestUUIDv7GeneratorRejectsSameMillisecondRegression(t *testing.T) {
	generator := &UUIDv7Generator{entropy: bytes.NewReader(bytes.Repeat([]byte{1}, 40))}
	first := time.Unix(2, 100_000)
	forward := first.Add(800 * time.Microsecond)

	for _, now := range []time.Time{first, forward, forward} {
		if _, err := generator.NewRequestID(now); err != nil {
			t.Fatalf("NewRequestID(%s) error = %v", now, err)
		}
	}

	backward := forward.Add(-100 * time.Microsecond)
	if _, err := generator.NewRequestID(backward); !errors.Is(err, ErrClockRegression) {
		t.Fatalf("same-millisecond regression error = %v, want %v", err, ErrClockRegression)
	}

	recovery := forward.Add(50 * time.Microsecond)
	if _, err := generator.NewRequestID(recovery); err != nil {
		t.Fatalf("NewRequestID after regression error = %v", err)
	}
}
func TestUUIDv7GeneratorEnforcesTimestampBounds(t *testing.T) {
	const maxMilliseconds = int64(1) << 48
	upperBound := time.Unix(
		maxMilliseconds/1_000,
		(maxMilliseconds%1_000)*int64(time.Millisecond),
	).UTC()

	tests := []struct {
		name       string
		now        time.Time
		wantPrefix string
		wantError  bool
	}{
		{
			name:       "exact unix epoch",
			now:        time.Unix(0, 0).UTC(),
			wantPrefix: "i_00000000-0000-7",
		},
		{
			name:       "exact last valid millisecond",
			now:        upperBound.Add(-time.Millisecond),
			wantPrefix: "i_ffffffff-ffff-7",
		},
		{
			name:      "exclusive upper bound",
			now:       upperBound,
			wantError: true,
		},
		{
			name: "far future UnixMilli overflow",
			now: time.Unix(
				18_446_744_073_709_551,
				616_000_000,
			).UTC(),
			wantError: true,
		},
		{
			name:      "pre epoch",
			now:       time.Unix(-1, 999_000_000).UTC(),
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			generator := &UUIDv7Generator{
				entropy: bytes.NewReader(bytes.Repeat([]byte{1}, 10)),
			}

			identifier, err := generator.NewRequestID(test.now)
			if test.wantError {
				if err == nil {
					t.Fatalf("NewRequestID(%s) succeeded", test.now)
				}
				if generator.hasTime || !generator.lastTime.IsZero() {
					t.Fatalf("rejected timestamp changed generator state: hasTime=%t lastTime=%s", generator.hasTime, generator.lastTime)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewRequestID(%s) error = %v", test.now, err)
			}
			if !strings.HasPrefix(identifier, test.wantPrefix) {
				t.Fatalf("NewRequestID(%s) = %q, want prefix %q", test.now, identifier, test.wantPrefix)
			}
		})
	}
}

func TestUUIDv7GeneratorStoresWallOnlyUTCState(t *testing.T) {
	now := time.Now()
	if now == now.Round(0) {
		t.Fatal("time.Now() did not include a monotonic clock reading")
	}

	generator := &UUIDv7Generator{
		entropy: bytes.NewReader(bytes.Repeat([]byte{1}, 10)),
	}
	if _, err := generator.NewRequestID(now); err != nil {
		t.Fatal(err)
	}

	want := now.Round(0).UTC()
	if generator.lastTime != want {
		t.Fatalf("stored lastTime = %#v, want wall-only UTC %#v", generator.lastTime, want)
	}
	if generator.lastTime != generator.lastTime.Round(0) {
		t.Fatal("stored lastTime retains a monotonic clock reading")
	}
}

func TestAtomicSequenceIsUniqueAndOrdered(t *testing.T) {
	var sequence AtomicSequence
	const count = 128
	values := make(chan uint64, count)
	var group sync.WaitGroup
	for range count {
		group.Add(1)
		go func() {
			defer group.Done()
			value, err := sequence.Next()
			if err != nil {
				t.Errorf("Next() error = %v", err)
				return
			}
			values <- value
		}()
	}
	group.Wait()
	close(values)

	seen := make(map[uint64]struct{}, count)
	for value := range values {
		seen[value] = struct{}{}
	}
	for value := uint64(1); value <= count; value++ {
		if _, ok := seen[value]; !ok {
			t.Fatalf("missing sequence value %d", value)
		}
	}
}

func TestAtomicSequenceRejectsNilAndExhaustion(t *testing.T) {
	var nilSequence *AtomicSequence
	if _, err := nilSequence.Next(); err == nil {
		t.Fatal("nil sequence succeeded")
	}
	var sequence AtomicSequence
	sequence.value.Store(^uint64(0))
	if _, err := sequence.Next(); err == nil {
		t.Fatal("exhausted sequence succeeded")
	}
}
