package childrun

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	appfollowup "github.com/irootkernel/mulgae/internal/app/followup"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestNewFollowupExecutorRejectsIncompleteAuthority(t *testing.T) {
	if executor, err := NewFollowupExecutor(nil, nil, nil, nil, nil, nil, ports.AnchoredRoot{}, FollowupExecutorConfig{}); executor != nil || err == nil {
		t.Fatal("NewFollowupExecutor accepted incomplete authority")
	}
}

func TestExecuteFollowupRejectsSessionMismatchBeforeExecution(t *testing.T) {
	t.Parallel()

	sourceSessionID := childrunSessionID(t, "s_019f596a-cfb0-7c67-b265-f37053d51ccf")
	executionSessionID := childrunSessionID(t, "s_019f596a-cfb1-7c67-b265-f37053d51ccf")
	execution := appfollowup.Execution{
		SessionID: executionSessionID,
		Source: appfollowup.VerifiedSource{
			ProviderInstance: "fake.logic",
			SessionID:        sourceSessionID,
			RunID:            childrunRunID(t, "r_019f596a-cfb2-7c67-b265-f37053d51ccf"),
			ReviewID:         childrunReviewID(t, "019f596a-cfb3-7c67-b265-f37053d51ccf"),
			Finding:          appfollowup.SourceFinding{ID: "F001", Role: domain.RoleLogic},
		},
		Current: appfollowup.CurrentTarget{Identity: childrunTarget(t)},
	}

	_, err := (&FollowupExecutor{}).ExecuteFollowup(context.Background(), execution)
	if err == nil || !strings.Contains(err.Error(), "trusted execution identity is invalid") {
		t.Fatalf("ExecuteFollowup session-mismatch error = %v, want identity rejection", err)
	}
}

func TestFollowupObservationFailurePreservesProviderOutputCause(t *testing.T) {
	packet, err := ports.NewProviderPacketFromBytes([]byte("provider input"))
	if err != nil {
		t.Fatal(err)
	}
	attemptID, err := domain.ParseAttemptID("a_019f596a-cfb4-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := ports.NewProviderInvocationWithPacket(
		domain.RoleSecurity, "zcode-security", attemptID, ports.ProviderInvocationInitial, packet,
		"i_019f596a-cfb5-7c67-b265-f37053d51ccf", "019f596a-cfb6-7c67-b265-f37053d51ccf",
	)
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := ports.NewStdinWriteReceipt(int64(len(packet.Bytes())), int64(len(packet.Bytes())), packet.Identity().CompleteSHA256(), true)
	if err != nil {
		t.Fatal(err)
	}
	exitCode := 0
	started := time.Unix(0, 0).UTC()
	process, err := ports.NewProcessObservation([]byte(`{"response":"malformed"}`), nil, &exitCode, ports.ProcessTerminationExited, stdin, started, started.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := ports.NewFailedProviderExecutionObservationWithCause(
		ports.ProviderExecutionStatusArtifactFailure, invocation, process, "invalid_provider_output",
		domain.DiagnosticCauseOutputEnvelopeInvalid, "", 4096, 4096,
	)
	if err != nil {
		t.Fatal(err)
	}
	failureErr := followupObservationFailure("zcode-security", domain.RoleSecurity, observation, errors.New("safe observation failure"))
	failures, ok := reviewrun.ProviderExecutionFailuresFromError(failureErr)
	if !ok || len(failures) != 1 {
		t.Fatalf("provider failures = %#v, present=%t", failures, ok)
	}
	if failures[0].ReasonCode() != string(review.AttemptConditionProviderOutputDecodeFailed) || failures[0].FailureClass() != domain.FailureInvalidOutput {
		t.Fatalf("provider failure = reason %q class %q", failures[0].ReasonCode(), failures[0].FailureClass())
	}
	state, cause := childDiagnosticTerminalDecision(failureErr)
	if state != domain.RunFailed || cause != domain.DiagnosticCauseOutputDecodeFailed {
		t.Fatalf("terminal decision = state %q cause %q", state, cause)
	}
}
