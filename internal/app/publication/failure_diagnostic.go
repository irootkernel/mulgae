package publication

import (
	"errors"
	"fmt"

	"github.com/irootkernel/mulgae/internal/domain"
)

// FailureDiagnostic is the redacted machine classification for a publication
// failure. It deliberately excludes native paths and underlying error text.
type FailureDiagnostic struct {
	phase      domain.RuntimeDiagnosticPhase
	cause      domain.RuntimeDiagnosticCause
	failure    string
	mitigation string
}

func (diagnostic FailureDiagnostic) Valid() bool {
	return diagnostic.phase.Valid() && diagnostic.cause.Valid() &&
		diagnostic.failure != "" && diagnostic.mitigation != ""
}

func (diagnostic FailureDiagnostic) Phase() domain.RuntimeDiagnosticPhase { return diagnostic.phase }
func (diagnostic FailureDiagnostic) Cause() domain.RuntimeDiagnosticCause { return diagnostic.cause }
func (diagnostic FailureDiagnostic) Failure() string                      { return diagnostic.failure }
func (diagnostic FailureDiagnostic) Mitigation() string                   { return diagnostic.mitigation }

type failureDiagnosticError struct {
	diagnostic FailureDiagnostic
	cause      error
}

func (failure *failureDiagnosticError) Error() string {
	if failure == nil {
		return "publication failure"
	}
	return fmt.Sprintf("publication: %s: %s", failure.diagnostic.phase, failure.diagnostic.cause)
}

func (failure *failureDiagnosticError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

func newFailureDiagnosticError(
	phase domain.RuntimeDiagnosticPhase,
	cause domain.RuntimeDiagnosticCause,
	failure string,
	mitigation string,
	err error,
) error {
	diagnostic := FailureDiagnostic{phase: phase, cause: cause, failure: failure, mitigation: mitigation}
	if !diagnostic.Valid() {
		return err
	}
	var existing *failureDiagnosticError
	if errors.As(err, &existing) {
		return err
	}
	return &failureDiagnosticError{diagnostic: diagnostic, cause: err}
}

// FailureDiagnosticFromError returns only the stable, redacted publication
// classification carried by err.
func FailureDiagnosticFromError(err error) (FailureDiagnostic, bool) {
	var failure *failureDiagnosticError
	if !errors.As(err, &failure) || failure == nil || !failure.diagnostic.Valid() {
		return FailureDiagnostic{}, false
	}
	return failure.diagnostic, true
}

func annotateFailure(stage string, _ string, err error) error {
	if diagnostic, ok := FailureDiagnosticFromError(err); ok && diagnostic.Valid() {
		return err
	}
	phase, cause := diagnosticClassification(stage)
	if !phase.Valid() || !cause.Valid() {
		return err
	}
	return newFailureDiagnosticError(phase, cause, safeFailureMessage(cause), safeMitigation(cause), err)
}

func buildFailure(
	phase domain.RuntimeDiagnosticPhase,
	cause domain.RuntimeDiagnosticCause,
	err error,
) error {
	return newFailureDiagnosticError(phase, cause, safeFailureMessage(cause), safeMitigation(cause), err)
}

func diagnosticClassification(stage string) (domain.RuntimeDiagnosticPhase, domain.RuntimeDiagnosticCause) {
	switch stage {
	case "publication.candidate", "publish.validate", "publish-next.validate":
		return domain.DiagnosticPhasePublicationCandidate, domain.DiagnosticCausePublicationCandidateInvalid
	case "publish-next.lock", "publish-next.commit":
		return domain.DiagnosticPhasePublicationStoreLock, domain.DiagnosticCausePublicationStoreLockFailed
	case "publish.build", "publish.preflight":
		return domain.DiagnosticPhasePublicationFinalReview, domain.DiagnosticCausePublicationSerializationFailed
	case "publication.stage", "recover.restage", "recover.final_staged":
		return domain.DiagnosticPhasePublicationStaging, domain.DiagnosticCausePublicationPathFailed
	case "publish.install_final", "recover.install":
		return domain.DiagnosticPhasePublicationInstallation, domain.DiagnosticCausePublicationInstallationFailed
	case "publish.commit_composite", "recover.commit_composite", "publish.manifest_committed", "recover.manifest_committed":
		return domain.DiagnosticPhasePublicationCommit, domain.DiagnosticCausePublicationCommitFailed
	case "publish.issue_review_id", "publish.persist_candidate", "publish.persist_support",
		"publish.verify_support", "publish.prepare_composite", "publish.content_validated",
		"publish.final_staged", "publish.final_installed", "publish.completed",
		"publication.journal", "publication.status", "publication.observe",
		"publication.snapshot", "publication.p2", "publication.support",
		"publish.recover", "recover.classify", "recover.corruption", "recover.diagnostic",
		"recover.material", "recover.observe", "recover.reconstruct":
		return domain.DiagnosticPhasePublicationPersistence, domain.DiagnosticCausePublicationPersistenceFailed
	default:
		return "", ""
	}
}

func safeFailureMessage(cause domain.RuntimeDiagnosticCause) string {
	switch cause {
	case domain.DiagnosticCausePublicationCandidateInvalid:
		return "publication candidate validation failed"
	case domain.DiagnosticCausePublicationEvidenceFailed:
		return "publication evidence verification failed"
	case domain.DiagnosticCausePublicationSchemaFailed:
		return "publication schema validation failed"
	case domain.DiagnosticCausePublicationSerializationFailed:
		return "publication serialization failed"
	case domain.DiagnosticCausePublicationStoreLockFailed:
		return "publication store lock failed"
	case domain.DiagnosticCausePublicationPathFailed:
		return "publication path preparation failed"
	case domain.DiagnosticCausePublicationInstallationFailed:
		return "publication installation failed"
	case domain.DiagnosticCausePublicationCommitFailed:
		return "publication commit failed"
	default:
		return "publication persistence failed"
	}
}

func safeMitigation(cause domain.RuntimeDiagnosticCause) string {
	if cause == domain.DiagnosticCausePublicationCandidateInvalid ||
		cause == domain.DiagnosticCausePublicationEvidenceFailed ||
		cause == domain.DiagnosticCausePublicationSchemaFailed ||
		cause == domain.DiagnosticCausePublicationSerializationFailed {
		return "rerun the review after correcting the publication invariant"
	}
	return "inspect the diagnostic phase and retry the full review"
}
