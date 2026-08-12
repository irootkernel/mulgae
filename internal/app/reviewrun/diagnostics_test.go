package reviewrun

import (
	"context"
	"errors"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestRuntimeDiagnosticTerminalDecisionDistinguishesDiagnosticPersistence(t *testing.T) {
	t.Parallel()

	diagnosticErr := diagnosticArtifactFailure("reviewrun.diagnostics.finalize", errors.New("injected"))
	state, cause, phase := runtimeDiagnosticTerminalDecision(nil, Result{}, diagnosticErr)
	if state != domain.RunFailed || cause != domain.DiagnosticCausePersistenceFailed || phase != domain.DiagnosticPhaseDiagnostics {
		t.Fatalf("diagnostic persistence decision = (%q, %q, %q)", state, cause, phase)
	}
	state, cause, phase = runtimeDiagnosticTerminalDecision(nil, Result{}, errors.Join(context.Canceled, diagnosticErr))
	if state != domain.RunFailed || cause != domain.DiagnosticCausePersistenceFailed || phase != domain.DiagnosticPhaseDiagnostics {
		t.Fatalf("mixed diagnostic persistence decision = (%q, %q, %q)", state, cause, phase)
	}

	publicationErr, err := domain.NewFailure("publication.install", domain.FailureArtifact, "publication failed", errors.New("injected"))
	if err != nil {
		t.Fatal(err)
	}
	state, cause, phase = runtimeDiagnosticTerminalDecision(nil, Result{}, publicationErr)
	if state != domain.RunFailed || cause != "" || phase != "" {
		t.Fatalf("unclassified publication decision = (%q, %q, %q), want no false diagnostic-persistence cause", state, cause, phase)
	}

	cancelledPublicationErr, err := domain.NewFailure("publish-next.lock", domain.FailureArtifact, "publication store lock failed", context.Canceled)
	if err != nil {
		t.Fatal(err)
	}
	state, cause, phase = runtimeDiagnosticTerminalDecision(context.Background(), Result{}, cancelledPublicationErr)
	if state != domain.RunFailed || cause != "" || phase != "" {
		t.Fatalf("artifact publication decision = (%q, %q, %q), want failed without a false diagnostic cause", state, cause, phase)
	}
	for _, class := range []domain.FailureClass{domain.FailureSecurityPolicy, domain.FailureInternal} {
		protected, createErr := domain.NewFailure("publish-next.lock", class, "protected publication failure", context.Canceled)
		if createErr != nil {
			t.Fatal(createErr)
		}
		state, cause, phase = runtimeDiagnosticTerminalDecision(context.Background(), Result{}, protected)
		if state != domain.RunFailed || cause != "" || phase != "" {
			t.Fatalf("%s publication decision = (%q, %q, %q), want failed", class, state, cause, phase)
		}
	}

	for _, cancellation := range []error{context.Canceled, context.DeadlineExceeded} {
		state, cause, phase = runtimeDiagnosticTerminalDecision(context.Background(), Result{}, cancellation)
		if state != domain.RunCancelled || cause != "" || phase != "" {
			t.Fatalf("pure cancellation decision for %v = (%q, %q, %q)", cancellation, state, cause, phase)
		}
	}
}

func TestRuntimeDiagnosticReferencePreservesAllocatedIdentity(t *testing.T) {
	t.Parallel()

	uri, _ := ports.NewSafeRelativePath(".mulgae/diagnostics/s_019f596a-cfe4-7c9c-b82e-7149158243ba/r_019f596a-cf80-7c67-b265-f37053d51ccf")
	sessionID, _ := domain.ParseSessionID("s_019f596a-cfe4-7c9c-b82e-7149158243ba")
	runID, _ := domain.ParseRunID("r_019f596a-cf80-7c67-b265-f37053d51ccf")
	cause := errors.New("publication failed")
	err := NewRuntimeDiagnosticReferenceErrorWithIdentity(uri, sessionID, runID, cause)

	gotSession, gotRun, ok := RuntimeDiagnosticIdentityFromError(err)
	if !ok || gotSession != sessionID || gotRun != runID || !errors.Is(err, cause) {
		t.Fatalf("diagnostic identity = (%q, %q, %t), err=%v", gotSession, gotRun, ok, err)
	}
}

func TestAllocatedRunIdentityDoesNotRequireInstalledDiagnostics(t *testing.T) {
	t.Parallel()

	sessionID, _ := domain.ParseSessionID("s_019f596a-cfe4-7c9c-b82e-7149158243ba")
	runID, _ := domain.ParseRunID("r_019f596a-cf80-7c67-b265-f37053d51ccf")
	cause := errors.New("diagnostic finalization failed")
	err := NewAllocatedRunIdentityError(sessionID, runID, cause)

	gotSession, gotRun, ok := RuntimeDiagnosticIdentityFromError(err)
	if !ok || gotSession != sessionID || gotRun != runID || !errors.Is(err, cause) {
		t.Fatalf("allocated identity = (%q, %q, %t), err=%v", gotSession, gotRun, ok, err)
	}
	if _, ok := RuntimeDiagnosticURIFromError(err); ok {
		t.Fatal("identity-only failure invented a diagnostic URI")
	}
}
