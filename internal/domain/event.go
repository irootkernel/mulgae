package domain

import (
	"fmt"
	"strings"
	"time"
)

// DomainEvent is an immutable coordinator-owned state transition record.
type DomainEvent struct {
	sequence    uint64
	occurredAt  time.Time
	kind        string
	aggregateID string
	payload     []byte
}

func NewDomainEvent(sequence uint64, occurredAt time.Time, kind, aggregateID string, payload []byte) (DomainEvent, error) {
	if sequence == 0 {
		return DomainEvent{}, fmt.Errorf("domain event: %w: sequence must be positive", ErrInvariant)
	}
	if occurredAt.IsZero() {
		return DomainEvent{}, fmt.Errorf("domain event: %w: timestamp must be non-zero", ErrInvariant)
	}
	if occurredAt.Location() != time.UTC {
		return DomainEvent{}, fmt.Errorf("domain event: %w: timestamp must be UTC", ErrInvariant)
	}
	if strings.TrimSpace(kind) == "" {
		return DomainEvent{}, fmt.Errorf("domain event: %w: kind must be non-empty", ErrInvariant)
	}
	if strings.TrimSpace(aggregateID) == "" {
		return DomainEvent{}, fmt.Errorf("domain event: %w: aggregate identity must be non-empty", ErrInvariant)
	}
	return DomainEvent{
		sequence:    sequence,
		occurredAt:  occurredAt,
		kind:        kind,
		aggregateID: aggregateID,
		payload:     append([]byte(nil), payload...),
	}, nil
}

func (event DomainEvent) Sequence() uint64      { return event.sequence }
func (event DomainEvent) OccurredAt() time.Time { return event.occurredAt }
func (event DomainEvent) Kind() string          { return event.kind }
func (event DomainEvent) AggregateID() string   { return event.aggregateID }
func (event DomainEvent) Payload() []byte       { return append([]byte(nil), event.payload...) }
