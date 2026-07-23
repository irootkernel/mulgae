package publication

import (
	"context"
	"fmt"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

type LifecycleEvent string

const (
	LifecyclePreparationStarted LifecycleEvent = "preparation_started"
	LifecycleStaged             LifecycleEvent = "staged"
	LifecycleInstalled          LifecycleEvent = "installed"
	LifecycleCommitted          LifecycleEvent = "committed"
	LifecycleFailed             LifecycleEvent = "failed"
)

func (event LifecycleEvent) Valid() bool {
	switch event {
	case LifecyclePreparationStarted, LifecycleStaged, LifecycleInstalled, LifecycleCommitted, LifecycleFailed:
		return true
	default:
		return false
	}
}

type LifecycleObserver interface {
	ObservePublicationLifecycle(context.Context, LifecycleEvent) error
}

type ObservedPublicationCommitter interface {
	PublishNextObserved(context.Context, ports.AnchoredRoot, PreparedCandidate, LifecycleObserver) (PublicationResult, error)
}

func observePublicationLifecycle(ctx context.Context, observer LifecycleObserver, event LifecycleEvent) error {
	if observer == nil || !event.Valid() {
		return nil
	}
	if err := observer.ObservePublicationLifecycle(context.WithoutCancel(ctx), event); err != nil {
		failure, failureErr := domain.NewFailure("publication.diagnostics", domain.FailureArtifact, "runtime diagnostics persistence failed", err)
		if failureErr != nil {
			return fmt.Errorf("publication lifecycle observer: %w", failureErr)
		}
		return failure
	}
	return nil
}
