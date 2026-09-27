package mulgae

import (
	"context"
	"errors"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// A missing publication can authorize diagnostic projection only when no other
// failure is present. Corruption, cancellation and cleanup errors stay failures.
func solelyMissingPublication(err error) bool {
	if err == ports.ErrPublicationRunNotFound {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		found := false
		for _, child := range joined.Unwrap() {
			if child == nil {
				continue
			}
			if !solelyMissingPublication(child) {
				return false
			}
			found = true
		}
		return found
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return solelyMissingPublication(wrapped.Unwrap())
	}
	return false
}

func (application *Application) inspectDiagnostic(ctx context.Context, request VerifiedReadRequest, root string) (execution, error) {
	if nilApplicationDependency(application.diagnosticQueries) {
		return execution{}, ports.ErrPublicationRunNotFound
	}
	_, artifactRoot, err := publicationRoots(root)
	if err != nil {
		return execution{}, err
	}
	runID, err := domain.ParseRunID(request.RunID)
	if err != nil {
		return execution{}, err
	}
	status, err := application.diagnosticQueries.ReadRunStatus(ctx, artifactRoot, runID)
	if err != nil {
		return execution{}, err
	}
	data, err := diagnosticStatusResultData(StatusRequest{runID: request.RunID}, status)
	if err != nil {
		return execution{}, err
	}
	if _, _, err = application.resolvePublicationRun(ctx, root, request.RunID); !solelyMissingPublication(err) {
		return execution{}, typedHandlerFailure("query.inspect", domain.FailureArtifact, "publication changed during diagnostic inspection", errors.New("observation changed"))
	}
	return execution{data: data, human: diagnosticStatusHumanOutput(status)}, nil
}
