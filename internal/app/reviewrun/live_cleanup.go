package reviewrun

import (
	"context"
	"errors"
	"fmt"

	"github.com/irootkernel/mulgae/internal/ports"
)

// LiveRunCleanup retains a source lease when provider termination is unproven.
// Retrying cleanup grants no review, replay, or publication authority.
type LiveRunCleanup struct {
	source          ports.LiveSourceReader
	provider        RunAuthority
	providerDrained bool
	sourceClosed    bool
}

func (cleanup *LiveRunCleanup) DrainAndClose(ctx context.Context) error {
	if cleanup == nil || ctx == nil {
		return fmt.Errorf("live cleanup: missing authority or context")
	}
	if !cleanup.providerDrained && !nilInterface(cleanup.provider) {
		if _, err := DrainRunAuthorityTerminal(ctx, cleanup.provider); err != nil {
			return err
		}
		cleanup.providerDrained = true
	}
	if cleanup.sourceClosed {
		return nil
	}
	_, bindingErr := cleanup.source.RevalidateExecution(context.WithoutCancel(ctx))
	closeErr := cleanup.source.Close()
	cleanup.sourceClosed = closeErr == nil
	if bindingErr != nil || closeErr != nil {
		return projectAdmissionFailure(errors.Join(bindingErr, closeErr))
	}
	return nil
}

type liveCleanupError struct {
	cause   error
	cleanup *LiveRunCleanup
}

func (err *liveCleanupError) Error() string {
	return "live review: terminal cleanup remains incomplete"
}
func (err *liveCleanupError) Unwrap() error                { return err.cause }
func (err *liveCleanupError) CleanupOwner() RunAuthority   { return err.cleanup.provider }
func (err *liveCleanupError) LiveCleanup() *LiveRunCleanup { return err.cleanup }

func LiveCleanupFromError(err error) (*LiveRunCleanup, bool) {
	var retained interface{ LiveCleanup() *LiveRunCleanup }
	if !errors.As(err, &retained) || retained.LiveCleanup() == nil {
		return nil, false
	}
	return retained.LiveCleanup(), true
}
