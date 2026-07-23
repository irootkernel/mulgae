package publication

import (
	"context"
	"errors"
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

type committedDiagnosticFailure struct {
	result PublicationResult
	cause  error
}

func (failure *committedDiagnosticFailure) Error() string {
	return "publication: committed P2 diagnostics persistence failed"
}

func (failure *committedDiagnosticFailure) Unwrap() error { return failure.cause }

func newCommittedDiagnosticFailure(result PublicationResult, cause error) error {
	return &committedDiagnosticFailure{result: result, cause: cause}
}

func committedPublicationResultFromError(err error) (PublicationResult, bool) {
	var retained *committedDiagnosticFailure
	if !errors.As(err, &retained) || retained == nil || retained.result.Decision().Authority() != domain.PublicationAuthorityP2 {
		return PublicationResult{}, false
	}
	if _, ok := retained.result.Snapshot(); !ok {
		return PublicationResult{}, false
	}
	return retained.result, true
}

// CommittedPublicationManifestPathFromError returns the manifest path retained
// by a post-commit diagnostic failure.
func CommittedPublicationManifestPathFromError(err error) (ports.SafeRelativePath, bool) {
	result, ok := committedPublicationResultFromError(err)
	if !ok {
		return ports.SafeRelativePath{}, false
	}
	snapshot, ok := result.Snapshot()
	if !ok || !snapshot.Manifest().Path().Valid() {
		return ports.SafeRelativePath{}, false
	}
	return snapshot.Manifest().Path(), true
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
