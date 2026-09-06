package ports

import (
	"context"

	"github.com/irootkernel/mulgae/internal/domain"
)

// QualificationProbeObservation is private process evidence, not admission or
// publication authority. The observer consumes it before the fixture is drained.
type QualificationProbeObservation struct {
	Provider        string
	Role            domain.Role
	Packet          []byte
	Version         ProcessObservation
	VersionError    error
	Capability      ProcessObservation
	CapabilityError error
	Err             error
}

type QualificationProbeObserver interface {
	ObserveQualificationProbe(context.Context, QualificationProbeObservation) error
}

type qualificationObserverKey struct{}

func WithQualificationProbeObserver(ctx context.Context, observer QualificationProbeObserver) context.Context {
	return context.WithValue(ctx, qualificationObserverKey{}, observer)
}

func ObserveQualificationProbe(ctx context.Context, observation QualificationProbeObservation) error {
	observer, ok := ctx.Value(qualificationObserverKey{}).(QualificationProbeObserver)
	if !ok {
		return nil
	}
	return observer.ObserveQualificationProbe(ctx, observation)
}
