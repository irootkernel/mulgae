package reviewrun

import (
	"bytes"
	"context"
	"errors"
	"io"
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

func TestPreparedChildDiagnosticsTransfersOnlyMatchingIdentity(t *testing.T) {
	ctx := context.Background()
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ids := &serviceIDs{}
	session, _ := ids.NewSessionID(serviceClock{}.Now())
	prepared, ctx, err := PrepareChildRunDiagnostics(ctx, ports.NewInMemoryRuntimeDiagnosticSinkFactory(), root, session, []domain.Role{domain.RoleLogic}, serviceClock{}, ids)
	if err != nil {
		t.Fatal(err)
	}
	wrong, _ := domain.ParseRunID("r_019f596a-cf80-7c67-b265-f37053d51ccf")
	if _, _, _, exists, err := TakePreparedRunDiagnostics(ctx, session, wrong); !exists || err == nil {
		t.Fatal("mismatched handoff accepted")
	}
	sink, started, seq, exists, err := TakePreparedRunDiagnostics(ctx, session, prepared.RunID())
	if err != nil || !exists || sink == nil || started.IsZero() || seq != 4 {
		t.Fatalf("handoff = %v %v %d %v %v", sink, started, seq, exists, err)
	}
	if err := prepared.Finish(ctx, nil); err != nil {
		t.Fatalf("transferred sink finalized twice: %v", err)
	}
	if _, _, _, _, err := TakePreparedRunDiagnostics(ctx, session, prepared.RunID()); err == nil {
		t.Fatal("duplicate handoff accepted")
	}
}

func TestPreparedChildDiagnosticsFailureHasNoPublication(t *testing.T) {
	ctx := context.Background()
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ids := &serviceIDs{}
	session, _ := ids.NewSessionID(serviceClock{}.Now())
	calls := []string{}
	factory := &serviceDiagnosticFactory{calls: &calls}
	prepared, ctx, err := PrepareChildRunDiagnostics(ctx, factory, root, session, []domain.Role{domain.RoleLogic}, serviceClock{}, ids)
	if err != nil {
		t.Fatal(err)
	}
	cause, _ := domain.NewFailure("qualification", domain.FailureInvalidOutput, "invalid fixture proof", nil)
	failure := prepared.Finish(ctx, cause)
	if !errors.Is(failure, cause) {
		t.Fatalf("primary cause lost: %v", failure)
	}
	if _, ok := RuntimeDiagnosticURIFromError(failure); !ok {
		t.Fatal("diagnostic reference missing")
	}
	gotSession, gotRun, ok := RuntimeDiagnosticIdentityFromError(failure)
	if !ok || gotSession != session || gotRun != prepared.RunID() {
		t.Fatal("allocated identity lost")
	}
	if len(factory.finalizeRequests) != 1 {
		t.Fatalf("finalized %d times", len(factory.finalizeRequests))
	}
	if uri, ok := factory.finalizeRequests[0].Status().P2URI(); ok || uri.String() != "" {
		t.Fatal("qualification failure acquired publication authority")
	}
}

func TestQualificationDiagnosticsRecordsSecurityDrop(t *testing.T) {
	for _, matching := range []bool{true, false} {
		name := "matching receipt"
		if !matching {
			name = "mismatched receipt"
		}
		t.Run(name, func(t *testing.T) {
			ctx, sink := newQualificationDiagnosticTestContext(t)
			sink.persist = func(request ports.RuntimeDiagnosticRawRequest) (ports.RuntimeDiagnosticRawResult, error) {
				drop, err := ports.NewDropMetadata("provider_stdout", "credential", 1, request.SourceIDs())
				if err != nil {
					t.Fatal(err)
				}
				result, err := ports.NewRuntimeDiagnosticRawResult(request.Stream(), ports.SafeRelativePath{}, &drop, 0)
				if err != nil {
					t.Fatal(err)
				}
				if !matching {
					drop, err = ports.NewDropMetadata("provider_stdout", "credential", 1, []string{"different-source"})
					if err != nil {
						t.Fatal(err)
					}
				}
				return result, ports.NewRuntimeDiagnosticSecurityRejectionError(drop, errors.New("screened"))
			}
			err := ports.ObserveQualificationProbe(ctx, ports.QualificationProbeObservation{
				Provider: "agy-documentation", Role: domain.RoleDocumentation, Packet: []byte("private packet"),
			})
			if !matching {
				var failure *domain.Failure
				if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact {
					t.Fatalf("mismatched drop did not fail closed: %v", err)
				}
				if len(sink.events) != 0 {
					t.Fatal("mismatched receipt produced an accepted diagnostic event")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			dropped := 0
			for _, event := range sink.events {
				if event.State != "security_dropped" {
					continue
				}
				dropped++
				if event.Event != domain.DiagnosticIOObserved || event.Operation != "request" ||
					event.Stream != domain.DiagnosticStdout || event.ArtifactRef != "" || event.Length != int64(len("private packet")) {
					t.Fatalf("invalid dropped-stream event: %+v", event)
				}
			}
			if dropped != 1 || sink.events[len(sink.events)-1].Outcome != qualificationOutcomeQualified {
				t.Fatalf("matching security drop stopped qualification: %+v", sink.events)
			}
		})
	}
}

func TestQualificationDiagnosticsRecoversProcessFailureStreams(t *testing.T) {
	ctx, sink := newQualificationDiagnosticTestContext(t)
	want := map[domain.RuntimeDiagnosticStream][]byte{
		domain.DiagnosticStdout: []byte("partial version output\n"),
		domain.DiagnosticStderr: []byte("version process failed\n"),
	}
	processErr, err := ports.NewProcessExecutionError(domain.DiagnosticCauseProviderProcessWaitFailed, "",
		want[domain.DiagnosticStdout], want[domain.DiagnosticStderr], errors.New("wait failed"))
	if err != nil {
		t.Fatal(err)
	}
	runtimeErr, err := ports.NewProviderRuntimeError(domain.DiagnosticCauseProviderProcessWaitFailed, processErr)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[domain.RuntimeDiagnosticStream]bool{}
	sink.persist = func(request ports.RuntimeDiagnosticRawRequest) (ports.RuntimeDiagnosticRawResult, error) {
		body, err := io.ReadAll(request.Source())
		if err != nil {
			t.Fatal(err)
		}
		if request.QualificationPhase() != "version" || seen[request.Stream()] || !bytes.Equal(body, want[request.Stream()]) {
			t.Fatalf("unexpected recovered stream: phase=%s stream=%s body=%q", request.QualificationPhase(), request.Stream(), body)
		}
		seen[request.Stream()] = true
		uri, err := ports.NewSafeRelativePath("qualification/version/" + string(request.Stream()) + ".raw")
		if err != nil {
			t.Fatal(err)
		}
		return ports.NewRuntimeDiagnosticRawResult(request.Stream(), uri, nil, int64(len(body)))
	}
	if err := ports.ObserveQualificationProbe(ctx, ports.QualificationProbeObservation{
		Provider: "agy-documentation", Role: domain.RoleDocumentation, VersionError: runtimeErr, Err: runtimeErr,
	}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 {
		t.Fatalf("recovered streams = %v", seen)
	}
	streamEvents := 0
	for _, event := range sink.events {
		if event.Operation != "version" {
			continue
		}
		streamEvents++
		if event.Cause != domain.DiagnosticCauseProviderProcessWaitFailed || event.ArtifactRef == "" ||
			event.Length != int64(len(want[event.Stream])) || event.HasExitCode || event.Termination != "" {
			t.Fatalf("recovered stream lost cause or invented process metadata: %+v", event)
		}
	}
	last := sink.events[len(sink.events)-1]
	if streamEvents != 2 || last.Outcome != qualificationOutcomeRejected || last.Cause != domain.DiagnosticCauseProviderProcessWaitFailed {
		t.Fatalf("process failure outcome = %+v, stream events = %d", last, streamEvents)
	}
}

type qualificationDiagnosticTestSink struct {
	ports.RuntimeDiagnosticSink
	persist func(ports.RuntimeDiagnosticRawRequest) (ports.RuntimeDiagnosticRawResult, error)
	events  []domain.RuntimeDiagnosticEventInput
}

func (sink *qualificationDiagnosticTestSink) PersistRaw(_ context.Context, request ports.RuntimeDiagnosticRawRequest) (ports.RuntimeDiagnosticRawResult, error) {
	return sink.persist(request)
}

func (sink *qualificationDiagnosticTestSink) Emit(ctx context.Context, draft domain.RuntimeDiagnosticEventDraft) (domain.RuntimeDiagnosticEvent, error) {
	sink.events = append(sink.events, draft.Input())
	return sink.RuntimeDiagnosticSink.Emit(ctx, draft)
}

func newQualificationDiagnosticTestContext(t *testing.T) (context.Context, *qualificationDiagnosticTestSink) {
	t.Helper()
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ids := &runIdentityTestIDs{}
	session, err := ids.NewSessionID(serviceClock{}.Now())
	if err != nil {
		t.Fatal(err)
	}
	prepared, ctx, err := PrepareChildRunDiagnostics(context.Background(), ports.NewInMemoryRuntimeDiagnosticSinkFactory(), root,
		session, []domain.Role{domain.RoleDocumentation}, serviceClock{}, ids)
	if err != nil {
		t.Fatal(err)
	}
	sink := &qualificationDiagnosticTestSink{RuntimeDiagnosticSink: prepared.lifecycle.sink}
	prepared.lifecycle.sink = sink
	return ctx, sink
}
