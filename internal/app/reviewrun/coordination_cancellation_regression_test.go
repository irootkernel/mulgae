package reviewrun

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type cancellationObservationStore struct {
	ownerTestStore
	bounded bool
}

func (s *cancellationObservationStore) UpdateObservation(ctx context.Context, root ports.AnchoredRoot, session domain.SessionID, run domain.RunID, reply ports.ReviewLockReply, at time.Time) (ports.ReviewLockRecord, error) {
	deadline, ok := ctx.Deadline()
	s.bounded = s.bounded && ok && time.Until(deadline) > 0 && time.Until(deadline) <= coordinationCallBudget
	if err := ctx.Err(); err != nil {
		return ports.ReviewLockRecord{}, err
	}
	return s.ownerTestStore.UpdateObservation(ctx, root, session, run, reply, at)
}

type cancellationAcquireTransport struct {
	*ownerTestTransport
	cancel context.CancelFunc
}

func (t *cancellationAcquireTransport) Acquire(ctx context.Context, raw []byte) (ports.ReviewLockReply, error) {
	reply, err := t.ownerTestTransport.Acquire(ctx, raw)
	t.cancel()
	return reply, err
}

func TestReviewCoordinatorAcquireCancellationAfterNativeAdmission(t *testing.T) {
	for _, queued := range []bool{true, false} {
		for _, persistenceFailure := range []bool{false, true} {
			name := map[bool]string{true: "queued", false: "granted"}[queued]
			if persistenceFailure {
				name += "/persistence_failure"
			} else {
				name += "/cancelled"
			}
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				store := &cancellationObservationStore{bounded: true}
				diskErr := errors.New("observation storage unavailable")
				if persistenceFailure {
					store.observationErr = diskErr
				}
				transport := &cancellationAcquireTransport{ownerTestTransport: &ownerTestTransport{queued: queued}, cancel: cancel}
				coordinator, err := NewReviewCoordinator(store, transport, ownerTestClock{}, "", false)
				if err != nil {
					t.Fatal(err)
				}
				owner, err := coordinator.startOwnedReview(ctx, ownerTestRequest(t), time.Minute)
				if owner != nil || err == nil {
					t.Fatalf("cancelled caller admitted owner: %v / %v", owner, err)
				}
				reason, ok := CoordinationFailureReason(err)
				if persistenceFailure {
					if !ok || reason != domain.DiagnosticCauseCoordinationPersistenceFailed || !errors.Is(err, diskErr) {
						t.Fatalf("real persistence failure was hidden: %q / %v", reason, err)
					}
				} else {
					var failure *domain.Failure
					if !ok || reason != domain.DiagnosticCauseCoordinationCancelled || !errors.As(err, &failure) || failure.Class() != domain.FailureCancelled || !errors.Is(err, context.Canceled) {
						t.Fatalf("settled admission cancellation misclassified: %q / %v", reason, err)
					}
					if store.record.ObservedRequest == nil || !store.record.ObservedRequest.State.IsTerminal() {
						t.Fatalf("terminal cancellation not persisted: %+v", store.record)
					}
					if transport.cancels != 1 || transport.releases != 0 {
						t.Fatalf("wrong cancellation disposition: %+v", transport.ownerTestTransport)
					}
				}
				if !store.bounded || store.record.LocalDrainState != ports.ReviewLocalDrainNotStarted || transport.acquires != 1 || transport.waits != 0 || !transport.current.State.IsTerminal() {
					t.Fatalf("unbounded persistence, duplicate admission or protected effects: store=%+v transport=%+v", store, transport.ownerTestTransport)
				}
			})
		}
	}
}
