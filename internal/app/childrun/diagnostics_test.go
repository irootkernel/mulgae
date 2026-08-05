package childrun

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type childDiagnosticRejectingSink struct {
	ports.RuntimeDiagnosticSink
	result ports.RuntimeDiagnosticRawResult
	err    error
}

func (sink childDiagnosticRejectingSink) PersistRaw(context.Context, ports.RuntimeDiagnosticRawRequest) (ports.RuntimeDiagnosticRawResult, error) {
	return sink.result, sink.err
}

func TestPersistObservationTreatsMatchedSecurityDropAsRedaction(t *testing.T) {
	packet, err := ports.NewProviderPacketFromBytes([]byte("provider input"))
	if err != nil {
		t.Fatal(err)
	}
	attemptID, err := domain.ParseAttemptID("a_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := ports.NewProviderInvocationWithPacket(
		domain.RoleSecurity, "zcode-security", attemptID, ports.ProviderInvocationInitial, packet,
		"i_019f596a-cf80-7c67-b265-f37053d51ccd", "019f596a-cf80-7c67-b265-f37053d51cce",
	)
	if err != nil {
		t.Fatal(err)
	}
	stdout := []byte(`{"resolution":"resolved"}`)
	result, err := ports.NewProviderResultForInput(stdout, packet.Identity())
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := ports.NewStdinWriteReceipt(int64(len(packet.Bytes())), int64(len(packet.Bytes())), packet.Identity().CompleteSHA256(), true)
	if err != nil {
		t.Fatal(err)
	}
	exitCode := 0
	started := time.Unix(0, 0).UTC()
	process, err := ports.NewProcessObservation(stdout, nil, &exitCode, ports.ProcessTerminationExited, stdin, started, started.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := ports.NewSuccessfulProviderExecutionObservation(invocation, result, process, 1024, 1024)
	if err != nil {
		t.Fatal(err)
	}
	drop, err := ports.NewDropMetadata("stdout", "credential_pattern", 1, []string{"provider:stdout"})
	if err != nil {
		t.Fatal(err)
	}
	dropped, err := ports.NewRuntimeDiagnosticRawResult(domain.DiagnosticStdout, ports.SafeRelativePath{}, &drop, 0)
	if err != nil {
		t.Fatal(err)
	}
	rejection := ports.NewRuntimeDiagnosticSecurityRejectionError(drop, errors.New("scanner rejected raw stream"))
	lifecycle := &childDiagnosticLifecycle{sink: childDiagnosticRejectingSink{result: dropped, err: rejection}}

	diagnostic, err := lifecycle.persistObservation(context.Background(), observation, 1)
	if err != nil {
		t.Fatalf("matched security drop became an artifact failure: %v", err)
	}
	if !diagnostic.stdoutSecurityDropped || diagnostic.stderrSecurityDropped {
		t.Fatalf("diagnostic drop = %#v, want stdout-only redaction", diagnostic)
	}
}

func TestChildDiagnosticTerminalDecisionReservesPersistenceForDiagnosticStage(t *testing.T) {
	diagnosticErr := childDiagnosticArtifactFailure(errors.New("write failed"))
	state, cause := childDiagnosticTerminalDecision(diagnosticErr)
	if state != domain.RunFailed || cause != domain.DiagnosticCausePersistenceFailed {
		t.Fatalf("diagnostic failure decision = state %q cause %q", state, cause)
	}

	publicationErr, err := domain.NewFailure("childrun.followup.publish", domain.FailureArtifact, "publication failed", errors.New("write failed"))
	if err != nil {
		t.Fatal(err)
	}
	state, cause = childDiagnosticTerminalDecision(publicationErr)
	if state != domain.RunFailed || cause != domain.DiagnosticCauseObservationInvalid {
		t.Fatalf("non-diagnostic artifact decision = state %q cause %q", state, cause)
	}

	providerArtifact := followupExecutionFailure("zcode-security", domain.RoleSecurity, review.AttemptConditionArtifactFailure, domain.FailureArtifact, errors.New("provider artifact failed"))
	state, cause = childDiagnosticTerminalDecision(providerArtifact)
	if state != domain.RunFailed || cause != domain.DiagnosticCauseObservationInvalid {
		t.Fatalf("provider artifact decision = state %q cause %q", state, cause)
	}
}
