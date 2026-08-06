package domain

import (
	"testing"
	"time"
)

func diagnosticTestIDs(t *testing.T) (SessionID, RunID, AttemptID) {
	t.Helper()
	session, _ := ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	run, _ := ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	attempt, _ := ParseAttemptID("a_019f596a-d048-79e7-b2b7-59822f012273")
	return session, run, attempt
}

func TestRuntimeDiagnosticEventIsClosedSafeAndStamped(t *testing.T) {
	t.Parallel()
	session, run, attempt := diagnosticTestIDs(t)
	draft, err := NewRuntimeDiagnosticEventDraft(RuntimeDiagnosticEventInput{
		Level: RuntimeDiagnosticInfo, Component: "provider", Operation: "observe", Event: DiagnosticIOObserved,
		SessionID: session, RunID: run, AttemptID: attempt, InvocationID: "i_019f596a-d04a-7a7a-8b3c-123456789abc",
		Role: RoleSecurity, Provider: "zcode-main", Stream: DiagnosticStderr, Offset: 4, Length: 9,
		ArtifactRef: "diagnostics/stream.raw",
	})
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, 7, 23, 4, 5, 6, 7, time.UTC)
	event, err := StampRuntimeDiagnosticEvent(draft, 7, stamp, 11)
	if err != nil {
		t.Fatal(err)
	}
	if event.SchemaVersion() != RuntimeDiagnosticSchemaVersion || event.Sequence() != 7 || event.Time() != stamp || event.ElapsedMillis() != 11 || event.Message() != "provider I/O observed" {
		t.Fatalf("unexpected event: %#v", event)
	}
}

func TestRuntimeDiagnosticEventRejectsUnsafeOrInconsistentFields(t *testing.T) {
	t.Parallel()
	session, run, _ := diagnosticTestIDs(t)
	base := RuntimeDiagnosticEventInput{Level: RuntimeDiagnosticInfo, Component: "runtime", Operation: "start", Event: DiagnosticRunStarted, SessionID: session, RunID: run}
	tests := []struct {
		name   string
		change func(*RuntimeDiagnosticEventInput)
	}{
		{"unknown level", func(in *RuntimeDiagnosticEventInput) { in.Level = "TRACE" }},
		{"unknown event", func(in *RuntimeDiagnosticEventInput) { in.Event = "arbitrary" }},
		{"path component", func(in *RuntimeDiagnosticEventInput) { in.Component = "internal/file" }},
		{"unsafe provider", func(in *RuntimeDiagnosticEventInput) { in.Provider = "secret\nvalue" }},
		{"unknown cause", func(in *RuntimeDiagnosticEventInput) { in.Cause = "free_form_error" }},
		{"noncanonical invocation", func(in *RuntimeDiagnosticEventInput) { in.InvocationID = "i_not-a-uuid" }},
		{"uppercase provider", func(in *RuntimeDiagnosticEventInput) { in.Provider = "ZCode" }},
		{"terminal failure at info", func(in *RuntimeDiagnosticEventInput) { in.Event = DiagnosticRunStopped }},
		{"mitigation at info", func(in *RuntimeDiagnosticEventInput) { in.Event = DiagnosticFallbackStarted }},
		{"range without stream", func(in *RuntimeDiagnosticEventInput) { in.Length = 1 }},
		{"escaped artifact", func(in *RuntimeDiagnosticEventInput) { in.ArtifactRef = "../escape" }},
		{"nul artifact", func(in *RuntimeDiagnosticEventInput) { in.ArtifactRef = "diagnostics/raw\x00.txt" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			input := base
			test.change(&input)
			if _, err := NewRuntimeDiagnosticEventDraft(input); err == nil {
				t.Fatal("invalid event accepted")
			}
		})
	}
	valid, _ := NewRuntimeDiagnosticEventDraft(base)
	if _, err := StampRuntimeDiagnosticEvent(valid, 0, time.Now().UTC(), 0); err == nil {
		t.Fatal("zero sequence accepted")
	}
	if _, err := StampRuntimeDiagnosticEvent(valid, 1, time.Now(), 0); err == nil && time.Now().Location() != time.UTC {
		t.Fatal("non-UTC timestamp accepted")
	}
}

func TestRuntimeDiagnosticClosedCodeSets(t *testing.T) {
	t.Parallel()
	if !DiagnosticWorkspaceCleanupCompleted.Valid() || RuntimeDiagnosticEventCode("custom").Valid() {
		t.Fatal("event code set is not closed")
	}
	if !DiagnosticCausePersistenceFailed.Valid() || RuntimeDiagnosticCause("native text").Valid() {
		t.Fatal("cause set is not closed")
	}
	if !DiagnosticCausePublicationInstallationFailed.Valid() || !DiagnosticPhasePublicationInstallation.Valid() || RuntimeDiagnosticPhase("native_path").Valid() {
		t.Fatal("publication diagnostic cause/phase sets are not closed")
	}
	for _, cause := range []RuntimeDiagnosticCause{
		DiagnosticCausePromptFilePreStartFailed,
		DiagnosticCausePromptFilePostEndFailed,
		DiagnosticCauseTransportReceiptMismatch,
		DiagnosticCauseLifecycleReceiptInvalid,
		DiagnosticCauseOutputFrameMismatch,
		DiagnosticCauseSignalReceiptMismatch,
	} {
		if !cause.Valid() {
			t.Fatalf("transport/lifecycle subtype %q is not closed", cause)
		}
	}
	if !DiagnosticStdout.Valid() || RuntimeDiagnosticStream("combined").Valid() {
		t.Fatal("stream set is not closed")
	}
}
