package runtime

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// ErrClockRegression reports a timestamp older than one already consumed.
var ErrClockRegression = errors.New("UUIDv7 clock regression")

const uuidV7MaxMilliseconds = int64(1) << 48

var (
	uuidV7UnixEpoch          = time.Unix(0, 0).UTC()
	uuidV7ExclusiveUpperTime = time.Unix(
		uuidV7MaxMilliseconds/1_000,
		(uuidV7MaxMilliseconds%1_000)*int64(time.Millisecond),
	).UTC()
)

var (
	_ ports.Clock                       = SystemClock{}
	_ ports.IDGenerator                 = (*UUIDv7Generator)(nil)
	_ ports.InvocationIdentityGenerator = (*UUIDv7Generator)(nil)
	_ ports.SequenceGenerator           = (*AtomicSequence)(nil)
)

// SystemClock provides the process wall clock through the application clock port.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

// UUIDv7Generator creates canonical identifiers from an injected timestamp and
// cryptographically random entropy. It rejects a timestamp older than any prior
// call so callers cannot silently hide wall-clock regression.
type UUIDv7Generator struct {
	mu       sync.Mutex
	entropy  io.Reader
	lastTime time.Time
	hasTime  bool
}

func NewUUIDv7Generator() *UUIDv7Generator {
	return &UUIDv7Generator{entropy: rand.Reader}
}

func (generator *UUIDv7Generator) NewSessionID(now time.Time) (domain.SessionID, error) {
	value, err := generator.newPrefixed(now, "s_")
	if err != nil {
		return domain.SessionID{}, err
	}
	return domain.ParseSessionID(value)
}

func (generator *UUIDv7Generator) NewRunID(now time.Time) (domain.RunID, error) {
	value, err := generator.newPrefixed(now, "r_")
	if err != nil {
		return domain.RunID{}, err
	}
	return domain.ParseRunID(value)
}

func (generator *UUIDv7Generator) NewAttemptID(now time.Time) (domain.AttemptID, error) {
	value, err := generator.newPrefixed(now, "a_")
	if err != nil {
		return domain.AttemptID{}, err
	}
	return domain.ParseAttemptID(value)
}

func (generator *UUIDv7Generator) NewReviewID(now time.Time) (domain.ReviewID, error) {
	value, err := generator.newPrefixed(now, "")
	if err != nil {
		return domain.ReviewID{}, err
	}
	return domain.ParseReviewID(value)
}

// NewRoleTaskID creates a role task identifier.
func (generator *UUIDv7Generator) NewRoleTaskID(now time.Time) (string, error) {
	return generator.newPrefixed(now, "rt_")
}

// NewSourceInvocationID creates a source invocation identifier.
func (generator *UUIDv7Generator) NewSourceInvocationID(now time.Time) (string, error) {
	return generator.newPrefixed(now, "i_")
}

// NewExecutionInvocationID creates an unprefixed execution invocation identifier.
func (generator *UUIDv7Generator) NewExecutionInvocationID(now time.Time) (string, error) {
	return generator.newPrefixed(now, "")
}

// NewRequestID creates the command-envelope request identifier.
func (generator *UUIDv7Generator) NewRequestID(now time.Time) (string, error) {
	return generator.newPrefixed(now, "i_")
}

func (generator *UUIDv7Generator) newPrefixed(now time.Time, prefix string) (string, error) {
	if generator == nil || generator.entropy == nil {
		return "", fmt.Errorf("UUIDv7 generator: nil entropy source")
	}
	if now.IsZero() {
		return "", fmt.Errorf("UUIDv7 generator: zero time")
	}
	// Round(0) strips Go's monotonic reading so regression checks use the same
	// wall-clock timeline encoded into UUIDv7.
	now = now.Round(0).UTC()
	if now.Before(uuidV7UnixEpoch) || !now.Before(uuidV7ExclusiveUpperTime) {
		return "", fmt.Errorf("UUIDv7 generator: timestamp outside 48-bit range")
	}
	millis := now.UnixMilli()

	generator.mu.Lock()
	defer generator.mu.Unlock()
	if generator.hasTime && now.Before(generator.lastTime) {
		return "", ErrClockRegression
	}

	var value [16]byte
	binary.BigEndian.PutUint64(value[:8], uint64(millis)<<16)
	if _, err := io.ReadFull(generator.entropy, value[6:]); err != nil {
		return "", fmt.Errorf("UUIDv7 generator: entropy: %w", err)
	}
	value[6] = value[6]&0x0f | 0x70
	value[8] = value[8]&0x3f | 0x80
	identifier := formatUUID(value)
	if identifier == "00000000-0000-7000-8000-000000000000" {
		return "", fmt.Errorf("UUIDv7 generator: zero-form UUIDv7 is not an issued identifier")
	}
	generator.lastTime = now
	generator.hasTime = true

	return prefix + identifier, nil
}

func formatUUID(value [16]byte) string {
	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		value[0:4],
		value[4:6],
		value[6:8],
		value[8:10],
		value[10:16],
	)
}

// AtomicSequence supplies exact process-local program order and fails closed on
// uint64 exhaustion.
type AtomicSequence struct {
	value atomic.Uint64
}

func (sequence *AtomicSequence) Next() (uint64, error) {
	if sequence == nil {
		return 0, fmt.Errorf("sequence generator: nil receiver")
	}
	for {
		current := sequence.value.Load()
		if current == ^uint64(0) {
			return 0, fmt.Errorf("sequence generator: exhausted")
		}
		if sequence.value.CompareAndSwap(current, current+1) {
			return current + 1, nil
		}
	}
}
