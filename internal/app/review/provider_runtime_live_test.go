package review

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type failingRecordingSink struct {
	*requirementsRecordingSink
	failEmitEvent domain.RuntimeDiagnosticEventCode
	emitErr       error
	persistRawErr error
	replaceErr    error
}

func (sink *failingRecordingSink) Emit(ctx context.Context, draft domain.RuntimeDiagnosticEventDraft) (domain.RuntimeDiagnosticEvent, error) {
	if sink.emitErr != nil && (sink.failEmitEvent == "" || draft.Input().Event == sink.failEmitEvent) {
		return domain.RuntimeDiagnosticEvent{}, sink.emitErr
	}
	return sink.requirementsRecordingSink.Emit(ctx, draft)
}

func (sink *failingRecordingSink) PersistRaw(ctx context.Context, request ports.RuntimeDiagnosticRawRequest) (ports.RuntimeDiagnosticRawResult, error) {
	if sink.persistRawErr != nil {
		return ports.RuntimeDiagnosticRawResult{}, sink.persistRawErr
	}
	return sink.requirementsRecordingSink.PersistRaw(ctx, request)
}

func (sink *failingRecordingSink) ReplaceInvocationStatus(ctx context.Context, status ports.RuntimeDiagnosticInvocationStatus) error {
	if sink.replaceErr != nil {
		return sink.replaceErr
	}
	return sink.requirementsRecordingSink.ReplaceInvocationStatus(ctx, status)
}

type funcObservedProvider struct {
	observe func(context.Context, ports.ProviderInvocation) (ports.ProviderExecutionObservation, error)
}

func (p *funcObservedProvider) Observe(ctx context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	return p.observe(ctx, invocation)
}

type runtimeLiveReader struct {
	coordinatorLiveReader
	binding      ports.ProjectBindingObservation
	err          error
	onRevalidate func()
}

func (reader *runtimeLiveReader) Root() ports.AnchoredRoot { return reader.binding.Root }
func (reader *runtimeLiveReader) RevalidateExecution(context.Context) (ports.ProjectBindingObservation, error) {
	if reader.onRevalidate != nil {
		reader.onRevalidate()
	}
	return reader.binding, reader.err
}

type runtimeLiveHome struct {
	ports.ReviewerHome
	root ports.AnchoredRoot
}

func (home runtimeLiveHome) Root() ports.AnchoredRoot { return home.root }
func (runtimeLiveHome) Revalidate() error             { return nil }

func TestProviderRuntimeLiveSourceBindsNativeExecutionAndEvidence(t *testing.T) {
	for _, test := range []struct {
		name    string
		rebound bool
		closed  bool
	}{
		{name: "verified live evidence"},
		{name: "changed source binding", closed: true},
		{name: "captured source bytes rejected", rebound: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
			path, _ := ports.NewSafeRelativePath("source.go")
			target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
			root, _ := ports.NewAnchoredRoot("/source")
			neutral, _ := ports.NewAnchoredRoot("/neutral")
			credential, _ := ports.NewAnchoredRoot("/credentials")
			reader := &runtimeLiveReader{coordinatorLiveReader: coordinatorLiveReader{target}, binding: ports.ProjectBindingObservation{Root: root, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}}}
			execution, err := ports.NewLiveReviewExecution(context.Background(), reader, runtimeLiveHome{root: neutral}, []ports.AnchoredRoot{credential})
			if err != nil {
				t.Fatal(err)
			}
			identity, _ := evidence.NewLiveSourceIdentity(target)
			_, job, material := providerRuntimeExplicitFixture(t, nil)
			job.target, err = identity.RunTarget()
			if err != nil {
				t.Fatal(err)
			}
			compiler, _ := prompt.NewCompiler(material.Prompt.TrustedTemplate(), explicitRuntimeTestIssuer{source: material.Prompt.Scope().SourceInvocationID(), execution: material.Prompt.Scope().ExecutionInvocationID()})
			coordinates := material.Prompt.Scope().FrameScope().Coordinates()
			material.Target = identity.Bytes()
			material.Prompt, err = compiler.Compile(prompt.CompileInput{Scope: coordinates, ReviewTarget: prompt.NewPayload(material.Target)})
			if err != nil {
				t.Fatal(err)
			}
			raw := []byte(`{"schema_version":"mulgae-provider-review-output.v1","summary":"Live observation.","completeness":"complete","limitations":[],"findings":[{"severity":"high","title":"Observed defect","description":"The observed source demonstrates the defect.","evidence":[{"current":{"path":"source.go","side":"worktree","line_start":1,"line_end":1,"quote":"observed\n"}}],"recommendation":"Correct the defect.","confidence":"high"}]}`)
			provider := &recordingObservedProvider{t: t, responses: []providerRuntimeObservation{{stdout: raw}}}
			runtime, err := NewObservedProviderInvocationRuntimeInLiveSource(provider, explicitRuntimePromptSource{material}, execution, newReviewValidator(t), providerRuntimeDiagnosticResolver{runID: job.RunID(), sink: &providerRuntimeRawSink{}})
			if err != nil {
				t.Fatal(err)
			}
			if test.rebound {
				material.CapturedArchive = []byte("captured source archive")
				runtime.source = explicitRuntimePromptSource{material}
			}
			if test.closed {
				reader.err = errors.New("source directory identity changed")
			}
			outcome := runtime.Invoke(context.Background(), job)
			if test.rebound || test.closed {
				if outcome.Succeeded() || len(provider.invocations) != 0 {
					t.Fatalf("unbound source reached provider: %#v", outcome)
				}
				return
			}
			output, ok := outcome.Output()
			if !outcome.Succeeded() || !ok || len(output.Findings()) != 1 || outcome.runtimeArtifactsExpected {
				t.Fatalf("live output or archive expectation: %#v", outcome)
			}
			invocation := provider.invocations[0]
			if _, live := invocation.LiveExecution(); !live {
				t.Fatal("live launch authority missing")
			}
			if _, captured := invocation.ExecutionWorkspace(); captured {
				t.Fatal("live invocation acquired snapshot authority")
			}
			if claim := output.evidence[0].Receipts()[0].Claim(); claim.SourceIdentitySHA256() != identity.SHA256() || claim.TargetSHA256() != "" {
				t.Fatal("source evidence became captured evidence")
			}
		})
	}
}

func TestProviderRuntimeNonRequirementsM1CitationFaultVsRealDrift(t *testing.T) {
	for _, scope := range []domain.LiveSourceScope{domain.LiveSourceWorkspace, domain.LiveSourceStage} {
		side := "worktree"
		if scope == domain.LiveSourceStage {
			side = "index"
		}
		makeFixture := func(t *testing.T, readErr error, responses ...[]byte) (*ProviderInvocationRuntime, InvocationJob, *requirementsRecordingSink) {
			t.Helper()
			selector, err := ports.NewLiveSourceSelector(scope, "")
			if err != nil {
				t.Fatal(err)
			}
			path, _ := ports.NewSafeRelativePath("source.go")
			var base ports.GitObjectID
			changes := []ports.LiveSourceChange{{Kind: "included", After: path}}
			if scope == domain.LiveSourceStage {
				base, _ = ports.ParseGitObjectID(strings.Repeat("a", 40))
				changes = []ports.LiveSourceChange{{Kind: "modified", Before: path, After: path}}
			}
			target, err := ports.NewLiveSourceTarget(selector, base, ports.GitObjectID{}, false, changes)
			if err != nil {
				t.Fatal(err)
			}
			root, _ := ports.NewAnchoredRoot("/source")
			neutral, _ := ports.NewAnchoredRoot("/neutral")
			credential, _ := ports.NewAnchoredRoot("/credentials")
			reader := &runtimeLiveReader{coordinatorLiveReader: coordinatorLiveReader{target}, binding: ports.ProjectBindingObservation{Root: root, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}}}
			execution, err := ports.NewLiveReviewExecution(context.Background(), reader, runtimeLiveHome{root: neutral}, []ports.AnchoredRoot{credential})
			if err != nil {
				t.Fatal(err)
			}
			identity, _ := evidence.NewLiveSourceIdentity(target)
			_, job, material := providerRuntimeExplicitFixture(t, nil)
			job.target, _ = identity.RunTarget()
			compiler, _ := prompt.NewCompiler(material.Prompt.TrustedTemplate(), explicitRuntimeTestIssuer{source: material.Prompt.Scope().SourceInvocationID(), execution: material.Prompt.Scope().ExecutionInvocationID()})
			material.Target = identity.Bytes()
			material.Prompt, err = compiler.Compile(prompt.CompileInput{Scope: material.Prompt.Scope().FrameScope().Coordinates(), ReviewTarget: prompt.NewPayload(material.Target)})
			if err != nil {
				t.Fatal(err)
			}
			provider := &recordingObservedProvider{t: t}
			for _, raw := range responses {
				provider.responses = append(provider.responses, providerRuntimeObservation{stdout: raw})
			}
			sink := &requirementsRecordingSink{}
			runtime, err := NewObservedProviderInvocationRuntimeInLiveSource(provider, requirementsTestPrompts{explicitRuntimePromptSource{material}}, execution, newReviewValidator(t), providerRuntimeDiagnosticResolver{runID: job.RunID(), sink: sink})
			if err != nil {
				t.Fatal(err)
			}
			if readErr != nil {
				runtime.verifier, _ = evidence.NewLiveVerifier(requirementsFaultReader{LiveSourceReader: execution.SourceReader(), err: readErr})
			}
			return runtime, job, sink
		}
		validFindingJSON := []byte(`{"schema_version":"mulgae-provider-review-output.v1","summary":"Live observation.","completeness":"complete","limitations":[],"findings":[{"severity":"high","title":"Observed defect","description":"The observed source demonstrates the defect.","evidence":[{"current":{"path":"source.go","side":"` + side + `","line_start":1,"line_end":1,"quote":"observed\n"}}],"recommendation":"Correct the defect.","confidence":"high"}]}`)

		t.Run(string(scope)+"/citation-fault-returns-unrepairable-evidence-without-pending-repair", func(t *testing.T) {
			for _, err := range []error{
				ports.NewLiveSourceCitationError(ports.LiveSourceUnavailable, errors.New("absent path")),
				ports.NewLiveSourceCitationError(ports.LiveSourceUnsafe, errors.New("excluded path")),
				ports.NewLiveSourceError(ports.LiveSourceInvalid, errors.New("wrong side")),
				ports.NewLiveSourceError(ports.LiveSourceUnsupported, errors.New("binary file")),
			} {
				runtime, job, sink := makeFixture(t, err, validFindingJSON)
				outcome := runtime.Invoke(context.Background(), job)
				cond, ok := outcome.Condition()
				if outcome.Succeeded() || !ok || cond != AttemptConditionUnrepairableEvidence {
					t.Fatalf("citation fault %v = cond:%q, want unrepairable_evidence_claim", err, cond)
				}
				if len(runtime.pending) != 0 {
					t.Fatalf("citation fault %v scheduled a broken missing-plan repair", err)
				}
				if sink.rawPersistCalls != 1 {
					t.Fatalf("citation fault %v rawPersistCalls = %d, want 1", err, sink.rawPersistCalls)
				}
			}
		})

		t.Run(string(scope)+"/real-drift-unsafe-fails-closed-and-captures-reject-true", func(t *testing.T) {
			for _, purpose := range []domain.InvocationPurpose{domain.InvocationInitial, domain.InvocationExtract} {
				var responses [][]byte
				if purpose == domain.InvocationExtract {
					responses = [][]byte{[]byte("# Prose report\n\nFinding.\n"), validFindingJSON}
				} else {
					responses = [][]byte{validFindingJSON}
				}
				runtime, job, sink := makeFixture(t, nil, responses...)
				if purpose == domain.InvocationExtract {
					if !runtime.Invoke(context.Background(), job).Succeeded() {
						t.Fatal("initial prose failed")
					}
					job, _ = newCoordinatorInvocationJob(job.SessionID(), job.RunID(), job.Role(), job.Route(), job.Target(), job.Limits(), job.AttemptID(), domain.InvocationExtract, 2)
				}
				runtime.verifier, _ = evidence.NewLiveVerifier(requirementsFaultReader{
					LiveSourceReader: runtime.liveExecution.SourceReader(),
					err:              ports.NewLiveSourceError(ports.LiveSourceUnsafe, errors.New("admitted file symlinked")),
				})
				outcome := runtime.Invoke(context.Background(), job)
				cond, ok := outcome.Condition()
				if outcome.Succeeded() || !ok || cond != AttemptConditionSecurityViolation || outcome.diagnosticCause != domain.DiagnosticCauseLiveSourceUnsafe {
					t.Fatalf("%s unsafe drift = cond:%q cause:%q, want security_violation/live_source_unsafe", purpose, cond, outcome.diagnosticCause)
				}
				wantRawCalls := 0
				if purpose == domain.InvocationExtract {
					wantRawCalls = 1 // only initial prose persisted raw; extraction was reject=true
				}
				if sink.rawPersistCalls != wantRawCalls {
					t.Fatalf("%s unsafe drift rawPersistCalls = %d, want %d", purpose, sink.rawPersistCalls, wantRawCalls)
				}
				capRec, captured := runtime.Capture(job.AttemptID(), invocationSequence(purpose))
				if !captured || len(capRec.Artifacts()) == 0 {
					t.Fatalf("%s unsafe drift missing capture markers", purpose)
				}
				for _, artifact := range capRec.Artifacts() {
					if !artifact.SecurityRejected() || len(artifact.Bytes()) != 0 {
						t.Fatalf("%s unsafe drift artifact leaked bytes: %+v", purpose, artifact)
					}
				}
			}
		})

		t.Run(string(scope)+"/real-drift-unavailable-and-conflict-fail-closed", func(t *testing.T) {
			for _, tc := range []struct {
				code ports.LiveSourceErrorCode
				want AttemptCondition
			}{
				{ports.LiveSourceUnavailable, AttemptConditionArtifactFailure},
				{ports.LiveSourceConflict, AttemptConditionConfigurationViolation},
				{ports.LiveSourceRevision, AttemptConditionConfigurationViolation},
				{ports.LiveSourceNoMergeBase, AttemptConditionConfigurationViolation},
			} {
				runtime, job, _ := makeFixture(t, ports.NewLiveSourceError(tc.code, errors.New("real drift")), validFindingJSON)
				outcome := runtime.Invoke(context.Background(), job)
				cond, ok := outcome.Condition()
				if outcome.Succeeded() || !ok || cond != tc.want {
					t.Fatalf("unmarked %q = cond:%q, want %q", tc.code, cond, tc.want)
				}
			}
		})
	}
}

func TestProviderRuntimeM2OriginatingSecurityDiagnosticCauses(t *testing.T) {
	t.Run("runtimeProviderErrorConditionAndCause preserves distinct security causes", func(t *testing.T) {
		stagingErr, err := ports.NewProviderRuntimeError(domain.DiagnosticCauseProviderOutputStagingViolation, errors.New("staged outside slot"))
		if err != nil {
			t.Fatal(err)
		}
		cleanupErr, err := ports.NewProcessExecutionError(domain.DiagnosticCauseProviderExecutionFailed, domain.DiagnosticCauseProcessGroupCleanupFailed, nil, nil, errors.New("cleanup failed"))
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name      string
			err       error
			wantCond  AttemptCondition
			wantCause domain.RuntimeDiagnosticCause
		}{
			{"workspace-snapshot-drift", ports.ErrWorkspaceSnapshotDrift, AttemptConditionSecurityViolation, domain.DiagnosticCauseWorkspaceRevalidationFailed},
			{"provider-packet-security", ports.ErrProviderPacketSecurity, AttemptConditionSecurityViolation, domain.DiagnosticCauseProviderPacketSecurityRejected},
			{"provider-runtime-staging", stagingErr, AttemptConditionSecurityViolation, domain.DiagnosticCauseProviderOutputStagingViolation},
			{"process-cleanup-security", cleanupErr, AttemptConditionSecurityViolation, domain.DiagnosticCauseProcessGroupCleanupFailed},
		} {
			cond, cause := runtimeProviderErrorConditionAndCause(context.Background(), tc.err)
			if cond != tc.wantCond || cause != tc.wantCause {
				t.Fatalf("%s = (%q, %q), want (%q, %q)", tc.name, cond, cause, tc.wantCond, tc.wantCause)
			}
		}
	})

	t.Run("liveExecution Revalidate failure sets WorkspaceRevalidationFailed", func(t *testing.T) {
		selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
		path, _ := ports.NewSafeRelativePath("source.go")
		target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
		root, _ := ports.NewAnchoredRoot("/source")
		neutral, _ := ports.NewAnchoredRoot("/neutral")
		credential, _ := ports.NewAnchoredRoot("/credentials")
		reader := &runtimeLiveReader{coordinatorLiveReader: coordinatorLiveReader{target}, binding: ports.ProjectBindingObservation{Root: root, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}}}
		execution, err := ports.NewLiveReviewExecution(context.Background(), reader, runtimeLiveHome{root: neutral}, []ports.AnchoredRoot{credential})
		if err != nil {
			t.Fatal(err)
		}
		identity, _ := evidence.NewLiveSourceIdentity(target)
		_, job, material := providerRuntimeExplicitFixture(t, nil)
		job.target, _ = identity.RunTarget()
		compiler, _ := prompt.NewCompiler(material.Prompt.TrustedTemplate(), explicitRuntimeTestIssuer{source: material.Prompt.Scope().SourceInvocationID(), execution: material.Prompt.Scope().ExecutionInvocationID()})
		material.Target = identity.Bytes()
		material.Prompt, err = compiler.Compile(prompt.CompileInput{Scope: material.Prompt.Scope().FrameScope().Coordinates(), ReviewTarget: prompt.NewPayload(material.Target)})
		if err != nil {
			t.Fatal(err)
		}
		provider := &recordingObservedProvider{t: t}
		runtime, err := NewObservedProviderInvocationRuntimeInLiveSource(provider, explicitRuntimePromptSource{material}, execution, newReviewValidator(t), providerRuntimeDiagnosticResolver{runID: job.RunID(), sink: &providerRuntimeRawSink{}})
		if err != nil {
			t.Fatal(err)
		}
		reader.err = errors.New("root anchor changed")
		outcome := runtime.Invoke(context.Background(), job)
		cond, ok := outcome.Condition()
		if outcome.Succeeded() || !ok || cond != AttemptConditionSecurityViolation || outcome.diagnosticCause != domain.DiagnosticCauseWorkspaceRevalidationFailed {
			t.Fatalf("liveExecution.Revalidate = (%q, %q), want security_violation/workspace_revalidation_failed", cond, outcome.diagnosticCause)
		}
	})

	t.Run("diagnostic security rejection sets DiagnosticSecurityRejected", func(t *testing.T) {
		drop, err := ports.NewDropMetadata("diagnostics", "secret_detector", 1, []string{"provider:stdout"})
		if err != nil {
			t.Fatal(err)
		}
		rejection := ports.NewRuntimeDiagnosticSecurityRejectionError(drop, errors.New("secret rejected"))
		_, job, _ := providerRuntimeExplicitFixture(t, nil)
		outcome := runtimePersistenceOutcome(job, rejection)
		cond, ok := outcome.Condition()
		if !ok || cond != AttemptConditionSecurityViolation || outcome.diagnosticCause != domain.DiagnosticCauseDiagnosticSecurityRejected {
			t.Fatalf("runtimePersistenceOutcome = (%q, %q), want security_violation/diagnostic_security_rejected", cond, outcome.diagnosticCause)
		}
	})

	t.Run("captureOutcome retains originating security violation on reject=true and reports artifact failure on non-security persistence error", func(t *testing.T) {
		runtime, job, _ := providerRuntimeExplicitFixture(t, nil)
		// Missing diagnostic inventory triggers a non-security persistence error when !reject,
		// while reject=true bypasses raw persistence and retains the originating security outcome.
		runtime.diagnostics = providerRuntimeDiagnosticResolver{runID: job.RunID(), sink: &providerRuntimeRawSink{}}
		secOutcome := runtimeConditionWithCause(job, AttemptConditionSecurityViolation, domain.DiagnosticCauseLiveSourceUnsafe)
		gotSec := runtime.captureOutcome(context.Background(), job, []byte(`{}`), []byte("raw"), nil, secOutcome)
		cond, ok := gotSec.Condition()
		if !ok || cond != AttemptConditionSecurityViolation || gotSec.diagnosticCause != domain.DiagnosticCauseLiveSourceUnsafe {
			t.Fatalf("security captureOutcome = (%q, %q), want security_violation/live_source_unsafe", cond, gotSec.diagnosticCause)
		}
		capRec, captured := runtime.Capture(job.AttemptID(), invocationSequence(job.Purpose()))
		if !captured || len(capRec.Artifacts()) == 0 {
			t.Fatal("security captureOutcome did not store security-rejected markers")
		}
		for _, artifact := range capRec.Artifacts() {
			if !artifact.SecurityRejected() || len(artifact.Bytes()) != 0 {
				t.Fatalf("security captureOutcome leaked bytes: %+v", artifact)
			}
		}

		// Non-security outcome hitting persistence error transitions to ArtifactFailure and clears pending repair.
		runtime.pending[job.AttemptID()] = InvocationRepairInput{}
		nonSecOutcome := runtimeCondition(job, AttemptConditionInvalidEvidenceClaim)
		gotNonSec := runtime.captureOutcome(context.Background(), job, []byte(`{}`), []byte("raw"), nil, nonSecOutcome)
		cond, ok = gotNonSec.Condition()
		if !ok || cond != AttemptConditionArtifactFailure {
			t.Fatalf("non-security persistence error captureOutcome = %q, want artifact_failure", cond)
		}
		if _, exists := runtime.pending[job.AttemptID()]; exists {
			t.Fatal("non-security persistence error did not clean up pending repair")
		}
	})

	t.Run("security-rejected failed observations do not persist raw streams and retain security violation", func(t *testing.T) {
		for _, withObserveErr := range []bool{false, true} {
			name := fmt.Sprintf("observeErr=%t", withObserveErr)
			t.Run(name, func(t *testing.T) {
				selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
				path, _ := ports.NewSafeRelativePath("source.go")
				target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
				root, _ := ports.NewAnchoredRoot("/source")
				neutral, _ := ports.NewAnchoredRoot("/neutral")
				credential, _ := ports.NewAnchoredRoot("/credentials")
				reader := &runtimeLiveReader{coordinatorLiveReader: coordinatorLiveReader{target}, binding: ports.ProjectBindingObservation{Root: root, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}}}
				execution, err := ports.NewLiveReviewExecution(context.Background(), reader, runtimeLiveHome{root: neutral}, []ports.AnchoredRoot{credential})
				if err != nil {
					t.Fatal(err)
				}
				identity, _ := evidence.NewLiveSourceIdentity(target)
				_, job, material := providerRuntimeExplicitFixture(t, nil)
				job.target, _ = identity.RunTarget()
				compiler, _ := prompt.NewCompiler(material.Prompt.TrustedTemplate(), explicitRuntimeTestIssuer{source: material.Prompt.Scope().SourceInvocationID(), execution: material.Prompt.Scope().ExecutionInvocationID()})
				material.Target = identity.Bytes()
				material.Prompt, err = compiler.Compile(prompt.CompileInput{Scope: material.Prompt.Scope().FrameScope().Coordinates(), ReviewTarget: prompt.NewPayload(material.Target)})
				if err != nil {
					t.Fatal(err)
				}
				provider := &funcObservedProvider{observe: func(_ context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
					process := providerRuntimeProcessObservation(t, invocation, []byte("secret provider stdout"), []byte("secret provider stderr"))
					obs, obsErr := ports.NewFailedProviderExecutionObservationWithCause(
						ports.ProviderExecutionStatusSecurityViolation,
						invocation,
						process,
						"staging_violation",
						domain.DiagnosticCauseProviderOutputStagingViolation,
						"",
					)
					if obsErr != nil {
						return ports.ProviderExecutionObservation{}, obsErr
					}
					if withObserveErr {
						boundaryErr, bErr := ports.NewProviderRuntimeError(domain.DiagnosticCauseProviderOutputStagingViolation, errors.New("staged escape"))
						if bErr != nil {
							return ports.ProviderExecutionObservation{}, bErr
						}
						return obs, boundaryErr
					}
					return obs, nil
				}}
				sink := &requirementsRecordingSink{}
				runtime, err := NewObservedProviderInvocationRuntimeInLiveSource(provider, explicitRuntimePromptSource{material}, execution, newReviewValidator(t), providerRuntimeDiagnosticResolver{runID: job.RunID(), sink: sink})
				if err != nil {
					t.Fatal(err)
				}
				outcome := runtime.Invoke(context.Background(), job)
				cond, ok := outcome.Condition()
				if outcome.Succeeded() || !ok || cond != AttemptConditionSecurityViolation || outcome.diagnosticCause != domain.DiagnosticCauseProviderOutputStagingViolation {
					t.Fatalf("%s = (%q, %q), want security_violation/provider_output_staging_violation", name, cond, outcome.diagnosticCause)
				}
				if sink.rawPersistCalls != 0 {
					t.Fatalf("%s leaked raw streams on security-rejected observation: rawPersistCalls=%d", name, sink.rawPersistCalls)
				}
				capRec, captured := runtime.Capture(job.AttemptID(), 1)
				if !captured || len(capRec.Artifacts()) == 0 {
					t.Fatalf("%s missing security-rejected capture markers", name)
				}
				for _, artifact := range capRec.Artifacts() {
					if !artifact.SecurityRejected() || len(artifact.Bytes()) != 0 {
						t.Fatalf("%s retained non-rejected bytes: %+v", name, artifact)
					}
				}
			})
		}
	})

	t.Run("observedStatusCondition delegates all security causes to SecurityViolation", func(t *testing.T) {
		for _, cause := range []domain.RuntimeDiagnosticCause{
			domain.DiagnosticCauseWorkspaceRevalidationFailed,
			domain.DiagnosticCauseTransportVerificationFailed,
			domain.DiagnosticCausePromptFilePreStartFailed,
			domain.DiagnosticCausePromptFilePostEndFailed,
			domain.DiagnosticCauseTransportReceiptMismatch,
			domain.DiagnosticCauseLifecycleReceiptInvalid,
			domain.DiagnosticCauseOutputFrameMismatch,
			domain.DiagnosticCauseSignalReceiptMismatch,
			domain.DiagnosticCauseObservationMismatch,
			domain.DiagnosticCauseProcessGroupCleanupFailed,
			domain.DiagnosticCauseProviderOutputStagingViolation,
			domain.DiagnosticCauseProviderOwnershipViolation,
			domain.DiagnosticCauseLiveSourceUnsafe,
			domain.DiagnosticCauseProviderPacketSecurityRejected,
			domain.DiagnosticCauseDiagnosticSecurityRejected,
		} {
			if got := observedStatusCondition(ports.ProviderExecutionStatusUnavailable, cause); got != AttemptConditionSecurityViolation {
				t.Fatalf("observedStatusCondition(unavailable, %q) = %q, want security_violation", cause, got)
			}
		}
	})

	t.Run("liveExecution Revalidate retains SecurityViolation on non-context drift even when context cancels", func(t *testing.T) {
		selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
		path, _ := ports.NewSafeRelativePath("source.go")
		target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
		root, _ := ports.NewAnchoredRoot("/source")
		neutral, _ := ports.NewAnchoredRoot("/neutral")
		credential, _ := ports.NewAnchoredRoot("/credentials")
		makeRuntime := func(t *testing.T, revalErr error, onRevalidate func()) (*ProviderInvocationRuntime, InvocationJob) {
			t.Helper()
			reader := &runtimeLiveReader{coordinatorLiveReader: coordinatorLiveReader{target}, binding: ports.ProjectBindingObservation{Root: root, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}}}
			execution, err := ports.NewLiveReviewExecution(context.Background(), reader, runtimeLiveHome{root: neutral}, []ports.AnchoredRoot{credential})
			if err != nil {
				t.Fatal(err)
			}
			identity, _ := evidence.NewLiveSourceIdentity(target)
			_, job, material := providerRuntimeExplicitFixture(t, nil)
			job.target, _ = identity.RunTarget()
			compiler, _ := prompt.NewCompiler(material.Prompt.TrustedTemplate(), explicitRuntimeTestIssuer{source: material.Prompt.Scope().SourceInvocationID(), execution: material.Prompt.Scope().ExecutionInvocationID()})
			material.Target = identity.Bytes()
			material.Prompt, err = compiler.Compile(prompt.CompileInput{Scope: material.Prompt.Scope().FrameScope().Coordinates(), ReviewTarget: prompt.NewPayload(material.Target)})
			if err != nil {
				t.Fatal(err)
			}
			rt, err := NewObservedProviderInvocationRuntimeInLiveSource(
				&recordingObservedProvider{t: t},
				explicitRuntimePromptSource{material},
				execution,
				newReviewValidator(t),
				providerRuntimeDiagnosticResolver{runID: job.RunID(), sink: &providerRuntimeRawSink{}},
			)
			if err != nil {
				t.Fatal(err)
			}
			reader.err = revalErr
			reader.onRevalidate = onRevalidate
			return rt, job
		}

		// Non-context revalidation error joined with context.Canceled -> SecurityViolation.
		rtJoined, jobJoined := makeRuntime(t, errors.Join(context.Canceled, errors.New("root anchor replaced")), nil)
		outJoined := rtJoined.Invoke(context.Background(), jobJoined)
		if cond, ok := outJoined.Condition(); !ok || cond != AttemptConditionSecurityViolation || outJoined.diagnosticCause != domain.DiagnosticCauseWorkspaceRevalidationFailed {
			t.Fatalf("joined drift+cancel = (%q, %q), want security_violation/workspace_revalidation_failed", cond, outJoined.diagnosticCause)
		}

		// Plain non-context revalidation error while invocationCtx cancels concurrently -> SecurityViolation.
		concurrentCtx, cancelConcurrent := context.WithCancel(context.Background())
		rtConcurrent, jobConcurrent := makeRuntime(t, errors.New("root anchor replaced"), cancelConcurrent)
		outConcurrent := rtConcurrent.Invoke(concurrentCtx, jobConcurrent)
		if cond, ok := outConcurrent.Condition(); !ok || cond != AttemptConditionSecurityViolation || outConcurrent.diagnosticCause != domain.DiagnosticCauseWorkspaceRevalidationFailed {
			t.Fatalf("concurrent cancel+drift = (%q, %q), want security_violation/workspace_revalidation_failed", cond, outConcurrent.diagnosticCause)
		}

		// Pure context.Canceled -> Cancelled; pure context.DeadlineExceeded -> Timeout.
		rtCancel, jobCancel := makeRuntime(t, fmt.Errorf("revalidate: %w", context.Canceled), nil)
		if cond, ok := rtCancel.Invoke(context.Background(), jobCancel).Condition(); !ok || cond != AttemptConditionCancelled {
			t.Fatalf("pure cancel revalidate = %q, want cancelled", cond)
		}
		rtDeadline, jobDeadline := makeRuntime(t, fmt.Errorf("revalidate: %w", context.DeadlineExceeded), nil)
		if cond, ok := rtDeadline.Invoke(context.Background(), jobDeadline).Condition(); !ok || cond != AttemptConditionTimeout {
			t.Fatalf("pure deadline revalidate = %q, want timeout", cond)
		}
	})

	t.Run("runtimeEvidenceErrorOutcome enforces canonical joined-error precedence and live-mode internal invariant", func(t *testing.T) {
		_, job, _ := providerRuntimeExplicitFixture(t, nil)
		secFailure, err := domain.NewFailure("evidence.verify", domain.FailureSecurityPolicy, "security policy", errors.New("secret"))
		if err != nil {
			t.Fatal(err)
		}
		intFailure, err := domain.NewFailure("evidence.verify", domain.FailureInternal, "internal", errors.New("bug"))
		if err != nil {
			t.Fatal(err)
		}
		// Citation fault joined with FailureSecurityPolicy -> SecurityViolation wins.
		joinedSec := errors.Join(ports.NewLiveSourceCitationError(ports.LiveSourceUnavailable, errors.New("absent")), secFailure)
		outSec := runtimeEvidenceErrorOutcome(context.Background(), job, true, joinedSec)
		if cond, ok := outSec.Condition(); !ok || cond != AttemptConditionSecurityViolation {
			t.Fatalf("citation+security failure = %q, want security_violation", cond)
		}
		// LiveSourceUnavailable joined with FailureInternal -> InternalInvariant wins.
		joinedInt := errors.Join(ports.NewLiveSourceError(ports.LiveSourceUnavailable, errors.New("drift")), intFailure)
		outInt := runtimeEvidenceErrorOutcome(context.Background(), job, true, joinedInt)
		if cond, ok := outInt.Condition(); !ok || cond != AttemptConditionInternalInvariant {
			t.Fatalf("unavailable+internal failure = %q, want internal_invariant", cond)
		}
		// Unexpected non-LiveSourceError in liveMode=true -> InternalInvariant (not planless InvalidProviderOutput).
		outLive := runtimeEvidenceErrorOutcome(context.Background(), job, true, errors.New("evidence verifier: source identity mismatch"))
		if cond, ok := outLive.Condition(); !ok || cond != AttemptConditionInternalInvariant {
			t.Fatalf("live unexpected verifier error = %q, want internal_invariant", cond)
		}
		// Non-live mode retains InvalidProviderOutput compatibility and DeadlineExceeded -> Timeout.
		outNonLive := runtimeEvidenceErrorOutcome(context.Background(), job, false, errors.New("immutable reader error"))
		if cond, ok := outNonLive.Condition(); !ok || cond != AttemptConditionInvalidProviderOutput {
			t.Fatalf("non-live verifier error = %q, want invalid_provider_output", cond)
		}
		outDeadline := runtimeEvidenceErrorOutcome(context.Background(), job, true, context.DeadlineExceeded)
		if cond, ok := outDeadline.Condition(); !ok || cond != AttemptConditionTimeout {
			t.Fatalf("deadline verifier error = %q, want timeout", cond)
		}

		// O2-1: canonical app.FailurePrecedence must govern joined errors (not policy.go's inverted ReduceAttemptConditions).
		unavailErr := ports.NewLiveSourceError(ports.LiveSourceUnavailable, errors.New("unavailable"))
		unsafeErr := ports.NewLiveSourceError(ports.LiveSourceUnsafe, errors.New("unsafe"))
		for name, joined := range map[string]error{
			"unavailable+unsafe": errors.Join(unavailErr, unsafeErr),
			"unsafe+unavailable": errors.Join(unsafeErr, unavailErr),
		} {
			got := runtimeEvidenceErrorOutcome(context.Background(), job, true, joined)
			if cond, ok := got.Condition(); !ok || cond != AttemptConditionSecurityViolation || got.diagnosticCause != domain.DiagnosticCauseLiveSourceUnsafe {
				t.Fatalf("%s = (%q, %q), want security_violation/live_source_unsafe", name, cond, got.diagnosticCause)
			}
		}
		gotUnavailSec := runtimeEvidenceErrorOutcome(context.Background(), job, true, errors.Join(unavailErr, secFailure))
		if cond, ok := gotUnavailSec.Condition(); !ok || cond != AttemptConditionSecurityViolation {
			t.Fatalf("unavailable+FailureSecurityPolicy = %q, want security_violation", cond)
		}
		gotTieBackfill := runtimeEvidenceErrorOutcome(context.Background(), job, true, errors.Join(secFailure, unsafeErr))
		if cond, ok := gotTieBackfill.Condition(); !ok || cond != AttemptConditionSecurityViolation || gotTieBackfill.diagnosticCause != domain.DiagnosticCauseLiveSourceUnsafe {
			t.Fatalf("FailureSecurityPolicy+unsafe tie = (%q, %q), want security_violation/live_source_unsafe", cond, gotTieBackfill.diagnosticCause)
		}
		provUnavail, err := domain.NewFailure("evidence.verify", domain.FailureProviderUnavailable, "provider unavailable", errors.New("down"))
		if err != nil {
			t.Fatal(err)
		}
		citeErr := ports.NewLiveSourceCitationError(ports.LiveSourceUnavailable, errors.New("absent"))
		if cond, ok := runtimeEvidenceErrorOutcome(context.Background(), job, true, errors.Join(citeErr, context.DeadlineExceeded)).Condition(); !ok || cond != AttemptConditionTimeout {
			t.Fatalf("citation+DeadlineExceeded = %q, want timeout", cond)
		}
		if cond, ok := runtimeEvidenceErrorOutcome(context.Background(), job, true, errors.Join(citeErr, provUnavail)).Condition(); !ok || cond != AttemptConditionProviderUnavailable {
			t.Fatalf("citation+FailureProviderUnavailable = %q, want provider_unavailable", cond)
		}
	})

	t.Run("O2-2 failing ReplaceInvocationStatus and failing Emit do not clobber SecurityViolation or MutationViolation", func(t *testing.T) {
		newLiveFixture := func(t *testing.T, provider ports.ObservedReviewProvider, sink ports.RuntimeDiagnosticSink) (*ProviderInvocationRuntime, InvocationJob) {
			t.Helper()
			selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
			path, _ := ports.NewSafeRelativePath("source.go")
			target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
			root, _ := ports.NewAnchoredRoot("/source")
			neutral, _ := ports.NewAnchoredRoot("/neutral")
			credential, _ := ports.NewAnchoredRoot("/credentials")
			reader := &runtimeLiveReader{coordinatorLiveReader: coordinatorLiveReader{target}, binding: ports.ProjectBindingObservation{Root: root, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}}}
			execution, err := ports.NewLiveReviewExecution(context.Background(), reader, runtimeLiveHome{root: neutral}, []ports.AnchoredRoot{credential})
			if err != nil {
				t.Fatal(err)
			}
			identity, _ := evidence.NewLiveSourceIdentity(target)
			_, job, material := providerRuntimeExplicitFixture(t, nil)
			job.target, _ = identity.RunTarget()
			compiler, _ := prompt.NewCompiler(material.Prompt.TrustedTemplate(), explicitRuntimeTestIssuer{source: material.Prompt.Scope().SourceInvocationID(), execution: material.Prompt.Scope().ExecutionInvocationID()})
			material.Target = identity.Bytes()
			material.Prompt, err = compiler.Compile(prompt.CompileInput{Scope: material.Prompt.Scope().FrameScope().Coordinates(), ReviewTarget: prompt.NewPayload(material.Target)})
			if err != nil {
				t.Fatal(err)
			}
			rt, err := NewObservedProviderInvocationRuntimeInLiveSource(
				provider,
				explicitRuntimePromptSource{material},
				execution,
				newReviewValidator(t),
				providerRuntimeDiagnosticResolver{runID: job.RunID(), sink: sink},
			)
			if err != nil {
				t.Fatal(err)
			}
			return rt, job
		}

		// 1. Failing ReplaceInvocationStatus during security observation rejection preserves SecurityViolation + cause.
		baseSink := &requirementsRecordingSink{}
		failReplaceSink := &failingRecordingSink{requirementsRecordingSink: baseSink, replaceErr: errors.New("status store unavailable")}
		secProvider := &funcObservedProvider{observe: func(_ context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
			process := providerRuntimeProcessObservation(t, invocation, []byte("secret"), nil)
			return ports.NewFailedProviderExecutionObservationWithCause(
				ports.ProviderExecutionStatusSecurityViolation, invocation, process, "staging_violation", domain.DiagnosticCauseProviderOutputStagingViolation, "",
			)
		}}
		rt1, job1 := newLiveFixture(t, secProvider, failReplaceSink)
		out1 := rt1.Invoke(context.Background(), job1)
		if cond, ok := out1.Condition(); !ok || cond != AttemptConditionSecurityViolation || out1.diagnosticCause != domain.DiagnosticCauseProviderOutputStagingViolation {
			t.Fatalf("ReplaceInvocationStatus failure clobbered SecurityViolation: (%q, %q)", cond, out1.diagnosticCause)
		}
		if baseSink.rawPersistCalls != 0 {
			t.Fatalf("rawPersistCalls = %d, want 0", baseSink.rawPersistCalls)
		}

		// 2. Failing Emit(DiagnosticValidationFailed) on non-requirements repair ownership violation still captures reject=true,
		// cleans up runtime.pending, and returns SecurityViolation/provider_ownership_violation.
		baseSink2 := &requirementsRecordingSink{}
		failEmitSink := &failingRecordingSink{
			requirementsRecordingSink: baseSink2,
			failEmitEvent:             domain.DiagnosticValidationFailed,
			emitErr:                   errors.New("emit storage down"),
			replaceErr:                errors.New("replace storage down"),
		}
		// Initial missing-summary JSON triggers repair; repair patch includes forbidden unknown/owned key -> ownershipViolation.
		initialInvalid := []byte(`{"schema_version":"mulgae-provider-review-output.v1","completeness":"complete","limitations":[],"findings":[]}`)
		repairOwnership := []byte(`{"schema_version":"mulgae-repair-patch.v1","repairs":[],"review_id":"forged"}`)
		call := 0
		repairProvider := &funcObservedProvider{observe: func(_ context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
			call++
			raw := initialInvalid
			if call == 2 {
				raw = repairOwnership
			}
			process := providerRuntimeProcessObservation(t, invocation, raw, nil)
			res, err := ports.NewProviderResultForInput(raw, invocation.InputIdentity())
			if err != nil {
				return ports.ProviderExecutionObservation{}, err
			}
			return ports.NewSuccessfulProviderExecutionObservation(invocation, res, process)
		}}
		// Allow initial invocation to succeed into pending repair before turning on sink failures.
		failEmitSink.emitErr = nil
		failEmitSink.replaceErr = nil
		rt2, job2 := newLiveFixture(t, repairProvider, failEmitSink)
		firstOut := rt2.Invoke(context.Background(), job2)
		if firstOut.Succeeded() || len(rt2.pending) != 1 {
			t.Fatalf("expected initial repair scheduling, got out=%+v pending=%d", firstOut, len(rt2.pending))
		}
		failEmitSink.emitErr = errors.New("emit storage down")
		failEmitSink.replaceErr = errors.New("replace storage down")
		repairJob, _ := newCoordinatorInvocationJob(job2.SessionID(), job2.RunID(), job2.Role(), job2.Route(), job2.Target(), job2.Limits(), job2.AttemptID(), domain.InvocationRepair, 2)
		secondOut := rt2.Invoke(context.Background(), repairJob)
		if cond, ok := secondOut.Condition(); !ok || cond != AttemptConditionSecurityViolation || secondOut.diagnosticCause != domain.DiagnosticCauseProviderOwnershipViolation {
			t.Fatalf("failing Emit/Replace on repair ownership violation = (%q, %q), want security_violation/provider_ownership_violation", cond, secondOut.diagnosticCause)
		}
		if len(rt2.pending) != 0 {
			t.Fatalf("failing Emit skipped pending repair cleanup: %d entries left", len(rt2.pending))
		}
		if baseSink2.rawPersistCalls != 1 {
			t.Fatalf("repair ownership violation leaked raw streams: rawPersistCalls=%d, want 1 (initial only)", baseSink2.rawPersistCalls)
		}
		capRec, captured := rt2.Capture(job2.AttemptID(), 2)
		if !captured || len(capRec.Artifacts()) == 0 {
			t.Fatal("repair ownership violation missing security-rejected capture markers")
		}
		for _, artifact := range capRec.Artifacts() {
			if !artifact.SecurityRejected() || len(artifact.Bytes()) != 0 {
				t.Fatalf("repair ownership violation artifact not security-rejected: %+v", artifact)
			}
		}
	})

	t.Run("O2-4 MutationViolation uses reject=true and higher-precedence observeErr is not downgraded by ProviderTimeout observation", func(t *testing.T) {
		newLiveFixture := func(t *testing.T, provider ports.ObservedReviewProvider, sink ports.RuntimeDiagnosticSink) (*ProviderInvocationRuntime, InvocationJob) {
			t.Helper()
			selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
			path, _ := ports.NewSafeRelativePath("source.go")
			target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
			root, _ := ports.NewAnchoredRoot("/source")
			neutral, _ := ports.NewAnchoredRoot("/neutral")
			credential, _ := ports.NewAnchoredRoot("/credentials")
			reader := &runtimeLiveReader{coordinatorLiveReader: coordinatorLiveReader{target}, binding: ports.ProjectBindingObservation{Root: root, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}}}
			execution, err := ports.NewLiveReviewExecution(context.Background(), reader, runtimeLiveHome{root: neutral}, []ports.AnchoredRoot{credential})
			if err != nil {
				t.Fatal(err)
			}
			identity, _ := evidence.NewLiveSourceIdentity(target)
			_, job, material := providerRuntimeExplicitFixture(t, nil)
			job.target, _ = identity.RunTarget()
			compiler, _ := prompt.NewCompiler(material.Prompt.TrustedTemplate(), explicitRuntimeTestIssuer{source: material.Prompt.Scope().SourceInvocationID(), execution: material.Prompt.Scope().ExecutionInvocationID()})
			material.Target = identity.Bytes()
			material.Prompt, err = compiler.Compile(prompt.CompileInput{Scope: material.Prompt.Scope().FrameScope().Coordinates(), ReviewTarget: prompt.NewPayload(material.Target)})
			if err != nil {
				t.Fatal(err)
			}
			rt, err := NewObservedProviderInvocationRuntimeInLiveSource(
				provider,
				explicitRuntimePromptSource{material},
				execution,
				newReviewValidator(t),
				providerRuntimeDiagnosticResolver{runID: job.RunID(), sink: sink},
			)
			if err != nil {
				t.Fatal(err)
			}
			return rt, job
		}

		// 1. ArtifactFailure / Cancelled observeErr paired with timed-out observation preserves higher precedence.
		artifactBoundary, err := ports.NewProviderRuntimeError(domain.DiagnosticCauseProviderOutputStagingCleanupFailed, errors.New("cleanup failed"))
		if err != nil {
			t.Fatal(err)
		}
		for name, tc := range map[string]struct {
			observeErr error
			want       AttemptCondition
		}{
			"artifact-beats-timeout":  {observeErr: artifactBoundary, want: AttemptConditionArtifactFailure},
			"cancelled-beats-timeout": {observeErr: context.Canceled, want: AttemptConditionCancelled},
		} {
			provider := &funcObservedProvider{observe: func(_ context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
				receipt, _ := ports.NewStdinWriteReceipt(int64(invocation.InputIdentity().ByteLength()), int64(invocation.InputIdentity().ByteLength()), invocation.CompleteStdinSHA256(), true)
				start := time.Now().UTC()
				proc, err := ports.NewProcessObservation(nil, nil, nil, ports.ProcessTerminationTimedOut, receipt, start, start.Add(time.Millisecond))
				if err != nil {
					return ports.ProviderExecutionObservation{}, err
				}
				obs, err := ports.NewFailedProviderExecutionObservationWithCause(ports.ProviderExecutionStatusTimedOut, invocation, proc, "provider_timeout", domain.DiagnosticCauseTimedOut, "")
				if err != nil {
					return ports.ProviderExecutionObservation{}, err
				}
				return obs, tc.observeErr
			}}
			rt, job := newLiveFixture(t, provider, &requirementsRecordingSink{})
			out := rt.Invoke(context.Background(), job)
			if cond, ok := out.Condition(); !ok || cond != tc.want {
				t.Fatalf("%s = %q, want %q", name, cond, tc.want)
			}
		}

		// 2. MutationViolation observation (both direct and promoted with observeErr) captures reject=true and survives sink errors.
		for _, withObserveErr := range []bool{false, true} {
			baseSink := &requirementsRecordingSink{}
			failSink := &failingRecordingSink{
				requirementsRecordingSink: baseSink,
				failEmitEvent:             domain.DiagnosticProcessExited,
				emitErr:                   errors.New("emit down"),
				replaceErr:                errors.New("replace down"),
			}
			provider := &funcObservedProvider{observe: func(_ context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
				process := providerRuntimeProcessObservation(t, invocation, []byte("mutated stdout"), []byte("mutated stderr"))
				obs, err := ports.NewFailedProviderExecutionObservationWithCause(
					ports.ProviderExecutionStatusMutationViolation, invocation, process, "workspace_mutated", domain.DiagnosticCauseWorkspaceRevalidationFailed, "",
				)
				if err != nil {
					return ports.ProviderExecutionObservation{}, err
				}
				if withObserveErr {
					return obs, context.Canceled
				}
				return obs, nil
			}}
			rt, job := newLiveFixture(t, provider, failSink)
			out := rt.Invoke(context.Background(), job)
			if cond, ok := out.Condition(); !ok || cond != AttemptConditionMutationViolation || out.diagnosticCause != domain.DiagnosticCauseWorkspaceRevalidationFailed {
				t.Fatalf("mutation violation (observeErr=%t) = (%q, %q), want mutation_violation/workspace_revalidation_failed", withObserveErr, cond, out.diagnosticCause)
			}
			if baseSink.rawPersistCalls != 0 {
				t.Fatalf("mutation violation (observeErr=%t) leaked raw streams: %d", withObserveErr, baseSink.rawPersistCalls)
			}
			capRec, captured := rt.Capture(job.AttemptID(), 1)
			if !captured || len(capRec.Artifacts()) == 0 {
				t.Fatalf("mutation violation (observeErr=%t) missing security-rejected capture markers", withObserveErr)
			}
			for _, artifact := range capRec.Artifacts() {
				if !artifact.SecurityRejected() || len(artifact.Bytes()) != 0 {
					t.Fatalf("mutation violation (observeErr=%t) artifact leaked bytes: %+v", withObserveErr, artifact)
				}
			}
		}
	})

	t.Run("O3-1 InternalInvariant is not downgraded by diagnostic Emit, PersistRaw, or ReplaceInvocationStatus errors", func(t *testing.T) {
		newLiveFixture := func(t *testing.T, provider ports.ObservedReviewProvider, sink ports.RuntimeDiagnosticSink) (*ProviderInvocationRuntime, InvocationJob) {
			t.Helper()
			selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
			path, _ := ports.NewSafeRelativePath("source.go")
			target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
			root, _ := ports.NewAnchoredRoot("/source")
			neutral, _ := ports.NewAnchoredRoot("/neutral")
			credential, _ := ports.NewAnchoredRoot("/credentials")
			reader := &runtimeLiveReader{coordinatorLiveReader: coordinatorLiveReader{target}, binding: ports.ProjectBindingObservation{Root: root, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}}}
			execution, err := ports.NewLiveReviewExecution(context.Background(), reader, runtimeLiveHome{root: neutral}, []ports.AnchoredRoot{credential})
			if err != nil {
				t.Fatal(err)
			}
			identity, _ := evidence.NewLiveSourceIdentity(target)
			_, job, material := providerRuntimeExplicitFixture(t, nil)
			job.target, _ = identity.RunTarget()
			compiler, _ := prompt.NewCompiler(material.Prompt.TrustedTemplate(), explicitRuntimeTestIssuer{source: material.Prompt.Scope().SourceInvocationID(), execution: material.Prompt.Scope().ExecutionInvocationID()})
			material.Target = identity.Bytes()
			material.Prompt, err = compiler.Compile(prompt.CompileInput{Scope: material.Prompt.Scope().FrameScope().Coordinates(), ReviewTarget: prompt.NewPayload(material.Target)})
			if err != nil {
				t.Fatal(err)
			}
			rt, err := NewObservedProviderInvocationRuntimeInLiveSource(
				provider,
				explicitRuntimePromptSource{material},
				execution,
				newReviewValidator(t),
				providerRuntimeDiagnosticResolver{runID: job.RunID(), sink: sink},
			)
			if err != nil {
				t.Fatal(err)
			}
			return rt, job
		}

		// 1. ProviderExecutionStatusInternalFailure with failing Emit, PersistRaw, and ReplaceInvocationStatus stays InternalInvariant.
		failSink1 := &failingRecordingSink{
			requirementsRecordingSink: &requirementsRecordingSink{},
			failEmitEvent:             domain.DiagnosticProcessExited,
			emitErr:                   errors.New("emit storage down"),
			persistRawErr:             errors.New("raw storage down"),
			replaceErr:                errors.New("status storage down"),
		}
		intProvider := &funcObservedProvider{observe: func(_ context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
			process := providerRuntimeProcessObservation(t, invocation, []byte("internal failure stdout"), []byte("internal failure stderr"))
			return ports.NewFailedProviderExecutionObservationWithCause(
				ports.ProviderExecutionStatusInternalFailure, invocation, process, "provider_internal", domain.DiagnosticCauseProviderExecutionFailed, "",
			)
		}}
		rt1, job1 := newLiveFixture(t, intProvider, failSink1)
		out1 := rt1.Invoke(context.Background(), job1)
		if cond, ok := out1.Condition(); !ok || cond != AttemptConditionInternalInvariant {
			t.Fatalf("ProviderExecutionStatusInternalFailure downgraded on sink errors = %q, want internal_invariant", cond)
		}

		// 2. Live verifier FailureInternal (rank 7) with failing PersistRaw and ReplaceInvocationStatus stays InternalInvariant.
		failSink2 := &failingRecordingSink{
			requirementsRecordingSink: &requirementsRecordingSink{},
			persistRawErr:             errors.New("raw storage down"),
			replaceErr:                errors.New("status storage down"),
		}
		validFindingJSON := []byte(`{"schema_version":"mulgae-provider-review-output.v1","summary":"Live observation.","completeness":"complete","limitations":[],"findings":[{"severity":"high","title":"Observed defect","description":"The observed source demonstrates the defect.","evidence":[{"current":{"path":"source.go","side":"worktree","line_start":1,"line_end":1,"quote":"observed\n"}}],"recommendation":"Correct the defect.","confidence":"high"}]}`)
		okProvider := &funcObservedProvider{observe: func(_ context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
			process := providerRuntimeProcessObservation(t, invocation, validFindingJSON, nil)
			res, err := ports.NewProviderResultForInput(validFindingJSON, invocation.InputIdentity())
			if err != nil {
				return ports.ProviderExecutionObservation{}, err
			}
			return ports.NewSuccessfulProviderExecutionObservation(invocation, res, process)
		}}
		rt2, job2 := newLiveFixture(t, okProvider, failSink2)
		intFailure, err := domain.NewFailure("evidence.verify", domain.FailureInternal, "internal verifier failure", errors.New("bug"))
		if err != nil {
			t.Fatal(err)
		}
		rt2.verifier, _ = evidence.NewLiveVerifier(requirementsFaultReader{LiveSourceReader: rt2.liveExecution.SourceReader(), err: intFailure})
		out2 := rt2.Invoke(context.Background(), job2)
		if cond, ok := out2.Condition(); !ok || cond != AttemptConditionInternalInvariant {
			t.Fatalf("live verifier FailureInternal downgraded on PersistRaw/Replace errors = %q, want internal_invariant", cond)
		}
	})
}

func TestRuntimeEvidenceErrorOutcomeEscalatesJoinedCitationAndOpaqueInLiveMode(t *testing.T) {
	_, job, _ := providerRuntimeExplicitFixture(t, nil)
	citationErr := ports.NewLiveSourceCitationError(ports.LiveSourceUnavailable, errors.New("absent cited path"))

	// Joined citation + opaque reader error in live mode must fail closed as InternalInvariant.
	joined := errors.Join(citationErr, errors.New("opaque reader failure"))
	out := runtimeEvidenceErrorOutcome(context.Background(), job, true, joined)
	if cond, ok := out.Condition(); !ok || cond != AttemptConditionInternalInvariant {
		t.Fatalf("joined citation+opaque in liveMode = (%q, %t), want internal_invariant", cond, ok)
	}

	// Pure citation error under active context remains bounded UnrepairableEvidence.
	pureOut := runtimeEvidenceErrorOutcome(context.Background(), job, true, citationErr)
	if cond, ok := pureOut.Condition(); !ok || cond != AttemptConditionUnrepairableEvidence {
		t.Fatalf("pure citation error in liveMode = (%q, %t), want unrepairable_evidence", cond, ok)
	}

	// Pure citation error under cancelled context projects as Cancelled rather than InternalInvariant.
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	canceledOut := runtimeEvidenceErrorOutcome(canceledCtx, job, true, citationErr)
	if cond, ok := canceledOut.Condition(); !ok || cond != AttemptConditionCancelled {
		t.Fatalf("pure citation error under canceled ctx = (%q, %t), want cancelled", cond, ok)
	}
}
