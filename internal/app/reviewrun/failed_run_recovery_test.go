package reviewrun

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type retentionBudgetKey struct{}

func TestServiceRecoveryRetentionBudgetDetachesCallerCancelAndSetsTenMinuteDeadline(t *testing.T) {
	for _, cancelledParent := range []bool{false, true} {
		name := "active parent"
		if cancelledParent {
			name = "cancelled parent"
		}
		t.Run(name, func(t *testing.T) {
			harness := newRecoveryFailureHarness(t, context.Canceled)
			parent := context.WithValue(context.Background(), retentionBudgetKey{}, "preserved")
			if cancelledParent {
				var cancel context.CancelFunc
				parent, cancel = context.WithCancel(parent)
				harness.provider.cancel = cancel
			}

			var drainDeadline time.Time
			var drainHasDeadline bool
			harness.authority.drainCheck = func(ctx context.Context) {
				if harness.authority.drains != 0 {
					return
				}
				if ctx.Err() != nil {
					t.Errorf("retention drain inherited caller cancellation: %v", ctx.Err())
				}
				if value := ctx.Value(retentionBudgetKey{}); value != "preserved" {
					t.Errorf("retention drain lost parent value: %v", value)
				}
				drainDeadline, drainHasDeadline = ctx.Deadline()
			}
			harness.diagnostics.emitCheck = func(ctx context.Context, event domain.RuntimeDiagnosticEventCode) {
				if event != domain.DiagnosticNamespaceDrainStarted {
					return
				}
				assertRetentionTenMinuteDeadline(t, "diagnostic emit", ctx)
			}
			harness.publisher.check = func(ctx context.Context) {
				if ctx.Err() != nil {
					t.Errorf("retention persist inherited caller cancellation: %v", ctx.Err())
				}
				if value := ctx.Value(retentionBudgetKey{}); value != "preserved" {
					t.Errorf("retention persist lost parent value: %v", value)
				}
				assertRetentionTenMinuteDeadline(t, "persist", ctx)
				if !drainHasDeadline {
					t.Error("retention drain context has no deadline")
					return
				}
				remaining := time.Until(drainDeadline)
				if remaining <= 0 || remaining > time.Minute+2*time.Second {
					t.Errorf("retention drain remaining = %s, want positive and <= 1m", remaining)
				}
				persistDeadline, ok := ctx.Deadline()
				if ok && drainDeadline.After(persistDeadline) {
					t.Errorf("retention drain deadline %v is after shared persist deadline %v", drainDeadline, persistDeadline)
				}
			}

			_, err := harness.service.Execute(parent, serviceRequest(t, harness.capture))
			if harness.provider.calls != 1 {
				t.Fatalf("provider execution calls = %d, want one", harness.provider.calls)
			}
			assertRecoveryOriginalFailure(t, err, domain.FailureCancelled, domain.RunCancelled, "")
			if harness.publisher.writes != 1 {
				t.Fatalf("retention persist writes = %d, want one", harness.publisher.writes)
			}
			if harness.publisher.checked != 1 {
				t.Fatalf("retention persist callback checks = %d, want one", harness.publisher.checked)
			}
		})
	}
}

func assertRetentionTenMinuteDeadline(t *testing.T, name string, ctx context.Context) {
	t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Errorf("retention %s context has no deadline", name)
		return
	}
	remaining := time.Until(deadline)
	if remaining < 9*time.Minute || remaining > 10*time.Minute+2*time.Second {
		t.Errorf("retention %s remaining = %s, want approximately 10m", name, remaining)
	}
}

func TestPreserveFailedRunRefusesExpiredContextBeforeCleanup(t *testing.T) {
	publisher := &recoveryFailurePublisher{}
	service := &Service{dependencies: Dependencies{Publication: publisher}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	err = service.preserveFailedRun(ctx, root, nil, review.CoordinatorResult{}, domain.TargetIdentity{}, domain.SeverityHigh, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("preserveFailedRun expired context: %v", err)
	}
	if publisher.writes != 0 {
		t.Fatalf("expired retention persisted %d times", publisher.writes)
	}
}

func TestDrainRunAuthorityTerminalForRetentionRefusesExpiredAndClipsAttempt(t *testing.T) {
	calls := []string{}
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	authority := &serviceAuthority{calls: &calls, terminal: serviceQualifiedTerminal(t)}
	if _, err := DrainRunAuthorityTerminalForRetention(expired, authority); !errors.Is(err, context.Canceled) {
		t.Fatalf("expired retention drain: %v", err)
	}
	if authority.drains != 0 {
		t.Fatalf("expired retention drain started %d attempts", authority.drains)
	}

	parent, stop := context.WithTimeout(context.Background(), FailedRunRecoveryRetentionTimeout)
	defer stop()
	authority = &serviceAuthority{
		calls:    &calls,
		terminal: serviceQualifiedTerminal(t),
		drainCheck: func(ctx context.Context) {
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatal("retention drain attempt has no deadline")
			}
			remaining := time.Until(deadline)
			if remaining <= 0 || remaining > time.Minute+2*time.Second {
				t.Fatalf("retention drain attempt remaining = %s, want positive and <= 1m", remaining)
			}
			if parentDeadline, ok := parent.Deadline(); ok && deadline.After(parentDeadline) {
				t.Fatalf("retention drain attempt %v is after shared budget %v", deadline, parentDeadline)
			}
		},
	}
	if _, err := DrainRunAuthorityTerminalForRetention(parent, authority); err != nil {
		t.Fatal(err)
	}
}

func TestDrainRunAuthorityTerminalForRetentionKeepsFirstErrorWhenContextExpires(t *testing.T) {
	calls := []string{}
	parent, cancel := context.WithCancel(context.Background())
	firstErr := errors.New("first drain failed with receipt")
	authority := &serviceAuthority{
		calls:                &calls,
		terminal:             serviceQualifiedTerminal(t),
		drainErrors:          []error{firstErr, errors.New("second drain must not run")},
		drainTerminalOnError: true,
		drainCheck: func(context.Context) {
			cancel()
		},
	}
	_, err := DrainRunAuthorityTerminalForRetention(parent, authority)
	if !errors.Is(err, firstErr) {
		t.Fatalf("retention drain error = %v, want first drain error", err)
	}
	if authority.drains != 1 {
		t.Fatalf("drains = %d, want one attempt and no retry", authority.drains)
	}
	var drainErr *terminalDrainCleanupError
	if !errors.As(err, &drainErr) || !drainErr.terminal.Valid() {
		t.Fatalf("lost typed drain error or receipt: %v", err)
	}
}

func TestDrainRunAuthorityTerminalForRetentionUsesEarlierParentDeadline(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	parentDeadline, ok := parent.Deadline()
	if !ok {
		t.Fatal("parent deadline missing")
	}
	calls := []string{}
	authority := &serviceAuthority{
		calls:       &calls,
		drainErrors: []error{context.DeadlineExceeded, errors.New("second drain must not run")},
		drainCheck: func(ctx context.Context) {
			deadline, ok := ctx.Deadline()
			if !ok || !deadline.Equal(parentDeadline) {
				t.Fatalf("drain attempt deadline = %v, want parent %v", deadline, parentDeadline)
			}
			<-ctx.Done()
		},
	}
	_, err := DrainRunAuthorityTerminalForRetention(parent, authority)
	if authority.drains != 1 {
		t.Fatalf("drains = %d, want expiry to prevent retry", authority.drains)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("retention drain error = %v, want parent deadline", err)
	}
}

func TestDetachedFailedRunRecoveryContextIgnoresCallerCancelAndSetsTenMinutes(t *testing.T) {
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), retentionBudgetKey{}, "preserved"))
	cancel()
	ctx, stop := DetachedFailedRunRecoveryContext(parent)
	defer stop()
	if ctx.Err() != nil {
		t.Fatalf("detached retention inherited cancellation: %v", ctx.Err())
	}
	if ctx.Value(retentionBudgetKey{}) != "preserved" {
		t.Fatalf("detached retention lost parent value: %v", ctx.Value(retentionBudgetKey{}))
	}
	assertRetentionTenMinuteDeadline(t, "detached helper", ctx)
}

func TestServiceRecoveryRetentionPreservesOriginalExecutionFailure(t *testing.T) {
	originals := []struct {
		name  string
		err   error
		class domain.FailureClass
		state domain.RunState
		cause domain.RuntimeDiagnosticCause
	}{
		{name: "cancellation", err: context.Canceled, class: domain.FailureCancelled, state: domain.RunCancelled},
		{name: "provider login", err: ports.ErrProviderLoginRequired, class: domain.FailureAuthentication, state: domain.RunFailed, cause: domain.DiagnosticCauseLoginRequired},
	}
	for _, original := range originals {
		for _, boundary := range []string{"unavailable", "storage", "recovery drain retry", "recovery drain deadline"} {
			t.Run(original.name+"/"+boundary, func(t *testing.T) {
				harness := newRecoveryFailureHarness(t, original.err)
				retentionFailure, err := domain.NewFailure("recovery.persist", domain.FailureArtifact, "injected storage failure", nil)
				if err != nil {
					t.Fatal(err)
				}
				var retentionErr error
				switch boundary {
				case "unavailable":
					harness.service.dependencies.Publication = servicePublisher{calls: harness.calls}
				case "storage":
					harness.publisher.err = retentionFailure
					retentionErr = retentionFailure
				case "recovery drain retry":
					recoveryDrainFailure := errors.New("recovery drain failed before mandatory cleanup retry")
					harness.authority.drainErrors = []error{recoveryDrainFailure, recoveryDrainFailure, nil}
					retentionErr = recoveryDrainFailure
				case "recovery drain deadline":
					harness.authority.drainErrors = []error{context.DeadlineExceeded, context.DeadlineExceeded, nil}
					retentionErr = context.DeadlineExceeded
				}

				_, err = harness.service.Execute(context.Background(), serviceRequest(t, harness.capture))
				if harness.provider.calls != 1 {
					t.Fatalf("provider execution calls = %d, want one", harness.provider.calls)
				}
				assertRecoveryOriginalFailure(t, err, original.class, original.state, original.cause)
				assertRecoveryDiagnosticFinalize(t, harness.diagnostics, original.state, original.cause)
				if retentionErr != nil && errors.Is(err, retentionErr) {
					t.Fatalf("retention failure gained operational authority: %v", err)
				}
				if _, ok := CleanupStateFromError(err); ok {
					t.Fatalf("successful cleanup retained retry authority: %v", err)
				}
				if !recoveryErrorChainContains(err, "recovery_") {
					t.Fatalf("recovery diagnostic absent: %v", err)
				}
				if harness.authority.drains == 0 {
					t.Fatalf("retention boundary did not drain provider authority: drains=%d", harness.authority.drains)
				}
				if boundary == "storage" {
					if !harness.lease.released || harness.lease.aborted {
						t.Fatalf("storage retention did not complete workspace release: released=%t aborted=%t", harness.lease.released, harness.lease.aborted)
					}
				} else if !harness.lease.aborted {
					t.Fatalf("retention boundary did not abort unreleased workspace: boundary=%s", boundary)
				}
				if boundary == "storage" && harness.publisher.writes != 1 {
					t.Fatalf("storage failure not reached: %d writes", harness.publisher.writes)
				}
				if (boundary == "recovery drain retry" || boundary == "recovery drain deadline") && harness.authority.drains != 3 {
					t.Fatalf("mandatory cleanup did not retry recovery drain: %d drains", harness.authority.drains)
				}
				if boundary == "recovery drain deadline" && errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("retention deadline became primary operational failure: %v", err)
				}
			})
		}
	}
}

func TestServiceRecoveryPersistentMandatoryCleanupRetainsTypedFailureAndOwner(t *testing.T) {
	originals := []struct {
		name  string
		err   error
		class domain.FailureClass
		cause domain.RuntimeDiagnosticCause
	}{
		{name: "cancellation", err: context.Canceled, class: domain.FailureCancelled},
		{name: "provider login", err: ports.ErrProviderLoginRequired, class: domain.FailureAuthentication, cause: domain.DiagnosticCauseLoginRequired},
	}
	for _, original := range originals {
		for _, cleanupClass := range []domain.FailureClass{domain.FailureArtifact, domain.FailureInternal} {
			t.Run(original.name+"/"+string(cleanupClass), func(t *testing.T) {
				harness := newRecoveryFailureHarness(t, original.err)
				cleanupFailure, err := domain.NewFailure("reviewrun.cleanup.provider", cleanupClass, "injected mandatory drain failure", nil)
				if err != nil {
					t.Fatal(err)
				}
				harness.authority.drainErrors = []error{cleanupFailure, cleanupFailure, cleanupFailure, cleanupFailure}

				_, err = harness.service.Execute(context.Background(), serviceRequest(t, harness.capture))
				if harness.provider.calls != 1 {
					t.Fatalf("provider execution calls = %d, want one", harness.provider.calls)
				}
				if err == nil || !errors.Is(err, cleanupFailure) {
					t.Fatalf("persistent mandatory cleanup failure = %v, want typed cleanup cause", err)
				}
				var primary *domain.Failure
				if !errors.As(err, &primary) || primary.Class() != original.class {
					t.Fatalf("original execution failure changed: %v", err)
				}
				if got := runtimeDiagnosticFailureClass(err); got != cleanupClass {
					t.Fatalf("operational failure precedence = %q, want %q", got, cleanupClass)
				}
				assertRecoveryDiagnosticFinalize(t, harness.diagnostics, domain.RunFailed, original.cause)
				state, ok := CleanupStateFromError(err)
				if !ok || state.ProviderOwner() != harness.authority || state.WorkspaceLease() != harness.lease || state.ProviderDrained() || state.WorkspaceDrained() {
					t.Fatalf("persistent cleanup lost retry authority: state=%#v present=%t", state, ok)
				}
				if harness.lease.aborted {
					t.Fatal("workspace abort ran without complete provider terminal evidence")
				}
				if harness.authority.drains != 4 {
					t.Fatalf("persistent mandatory cleanup drain count = %d, want four attempts", harness.authority.drains)
				}
			})
		}
	}
}

func TestServiceRecoveryDiagnosticRefusalPreservesPrimaryAndHidesRawCause(t *testing.T) {
	harness := newRecoveryFailureHarness(t, context.Canceled)
	refusal := errors.New("private diagnostic sink refusal: /private/provider/stderr")
	harness.diagnostics.refuseEvent = domain.DiagnosticNamespaceDrainStarted
	harness.diagnostics.refusal = refusal

	_, err := harness.service.Execute(context.Background(), serviceRequest(t, harness.capture))
	if harness.provider.calls != 1 {
		t.Fatalf("provider execution calls = %d, want one", harness.provider.calls)
	}
	assertRecoveryOriginalFailure(t, err, domain.FailureCancelled, domain.RunCancelled, "")
	assertRecoveryDiagnosticFinalize(t, harness.diagnostics, domain.RunCancelled, "")
	if strings.Contains(err.Error(), refusal.Error()) {
		t.Fatalf("diagnostic refusal leaked raw cause: %v", err)
	}
	if !recoveryErrorChainContains(err, "reviewrun.diagnostics.emit") {
		t.Fatalf("diagnostic refusal classification was lost from the private error chain: %v", err)
	}
	if !recoveryErrorChainContains(err, "recovery_diagnostics_failed") {
		t.Fatalf("diagnostic refusal recovery context was lost from the private error chain: %v", err)
	}
	if harness.diagnostics.refusals != 1 {
		t.Fatalf("diagnostic refusal count = %d, want one", harness.diagnostics.refusals)
	}
	if harness.authority.drains != 1 || !harness.lease.aborted {
		t.Fatalf("diagnostic refusal did not leave mandatory cleanup complete: drains=%d aborted=%t", harness.authority.drains, harness.lease.aborted)
	}
	if _, ok := CleanupStateFromError(err); ok {
		t.Fatalf("successful mandatory cleanup retained retry authority: %v", err)
	}
}

func TestServiceRecoveryRetentionUnavailableReportsIndependentWorkspaceAbortFailure(t *testing.T) {
	originals := []struct {
		name  string
		err   error
		class domain.FailureClass
		cause domain.RuntimeDiagnosticCause
	}{
		{name: "cancellation", err: context.Canceled, class: domain.FailureCancelled},
		{name: "provider login", err: ports.ErrProviderLoginRequired, class: domain.FailureAuthentication, cause: domain.DiagnosticCauseLoginRequired},
	}
	for _, original := range originals {
		for _, cleanupClass := range []domain.FailureClass{domain.FailureArtifact, domain.FailureInternal} {
			t.Run(original.name+"/"+string(cleanupClass), func(t *testing.T) {
				harness := newRecoveryFailureHarness(t, original.err)
				harness.service.dependencies.Publication = servicePublisher{calls: harness.calls}
				workspaceFailure, err := domain.NewFailure("reviewrun.cleanup.workspace", cleanupClass, "injected workspace abort failure", nil)
				if err != nil {
					t.Fatal(err)
				}
				harness.lease.abortErr = workspaceFailure

				_, err = harness.service.Execute(context.Background(), serviceRequest(t, harness.capture))
				if harness.provider.calls != 1 {
					t.Fatalf("provider execution calls = %d, want one", harness.provider.calls)
				}
				if err == nil || !errors.Is(err, workspaceFailure) {
					t.Fatalf("workspace abort failure = %v, want typed cleanup cause", err)
				}
				var primary *domain.Failure
				if !errors.As(err, &primary) || primary.Class() != original.class {
					t.Fatalf("original execution failure changed: %v", err)
				}
				if got := runtimeDiagnosticFailureClass(err); got != cleanupClass {
					t.Fatalf("workspace cleanup precedence = %q, want %q", got, cleanupClass)
				}
				state, ok := CleanupStateFromError(err)
				if !ok || state.ProviderOwner() != harness.authority || state.WorkspaceLease() != harness.lease || !state.ProviderDrained() || state.WorkspaceDrained() {
					t.Fatalf("workspace cleanup lost independent retry authority: state=%#v present=%t", state, ok)
				}
				assertRecoveryDiagnosticFinalize(t, harness.diagnostics, domain.RunFailed, original.cause)
				if !harness.lease.aborted || harness.authority.drains != 1 {
					t.Fatalf("workspace abort was not attempted after provider drain: drains=%d aborted=%t", harness.authority.drains, harness.lease.aborted)
				}
				if !recoveryErrorChainContains(err, "recovery_store_unavailable") {
					t.Fatalf("retention-unavailable classification was lost from the private error chain: %v", err)
				}
			})
		}
	}
}

func assertRecoveryOriginalFailure(t *testing.T, err error, wantClass domain.FailureClass, wantState domain.RunState, wantCause domain.RuntimeDiagnosticCause) {
	t.Helper()
	if err == nil {
		t.Fatal("review execution unexpectedly succeeded")
	}
	var primary *domain.Failure
	if !errors.As(err, &primary) || primary.Class() != wantClass {
		t.Fatalf("original execution failure = %v, want %q", err, wantClass)
	}
	if got := runtimeDiagnosticFailureClass(err); got != wantClass {
		t.Fatalf("retention changed operational failure precedence = %q, want %q", got, wantClass)
	}
	state, cause, phase := runtimeDiagnosticTerminalDecision(context.Background(), Result{}, err)
	if state != wantState || cause != wantCause || phase != "" {
		t.Fatalf("diagnostic terminal decision = (%q, %q, %q), want (%q, %q, empty)", state, cause, phase, wantState, wantCause)
	}
}

func assertRecoveryDiagnosticFinalize(t *testing.T, diagnostics *serviceDiagnosticFactory, wantState domain.RunState, wantCause domain.RuntimeDiagnosticCause) {
	t.Helper()
	if len(diagnostics.finalizeRequests) != 1 {
		t.Fatalf("diagnostic finalize request count = %d, want one", len(diagnostics.finalizeRequests))
	}
	request := diagnostics.finalizeRequests[0]
	if request.State() != wantState || request.Cause() != wantCause {
		t.Fatalf("diagnostic finalize request = (%q, %q), want (%q, %q)", request.State(), request.Cause(), wantState, wantCause)
	}
}

func recoveryErrorChainContains(err error, want string) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), want) {
		return true
	}
	switch unwrapped := err.(type) {
	case interface{ Unwrap() []error }:
		for _, child := range unwrapped.Unwrap() {
			if recoveryErrorChainContains(child, want) {
				return true
			}
		}
	case interface{ Unwrap() error }:
		return recoveryErrorChainContains(unwrapped.Unwrap(), want)
	}
	return false
}

type recoveryFailureHarness struct {
	calls       *[]string
	lease       *serviceLease
	capture     *serviceCapture
	provider    *recoveryFailureProvider
	authority   *recoveryFailureAuthority
	service     *Service
	diagnostics *serviceDiagnosticFactory
	publisher   *recoveryFailurePublisher
}

func newRecoveryFailureHarness(t *testing.T, providerErr error) *recoveryFailureHarness {
	t.Helper()
	calls := []string{}
	lease := newServiceLease(t, &calls)
	target := reviewRunPatchTarget(t)
	request, err := ports.NewWorkspaceSnapshotRequest(nil, "recovery-test")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceHead: nil})
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewCapturedReviewMaterialWithEvidence(target, request, nil, evidence)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := ports.MarshalCapturedReviewMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewImmutableReviewInputWithCapturedArchive(target, nil, false, nil, false, archive)
	if err != nil {
		t.Fatal(err)
	}
	clean, err := ports.NewReviewInputDetection(ports.ReviewInputClean, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := NewCapturedRunInput(input, lease, serviceReader{}, &packetDetectorFake{detection: clean})
	if err != nil {
		t.Fatal(err)
	}
	capture := &serviceCapture{captured: captured}
	provider := &recoveryFailureProvider{err: providerErr}
	authority := &recoveryFailureAuthority{
		serviceAuthority: serviceAuthority{calls: &calls, terminal: serviceQualifiedTerminal(t)},
		provider:         provider,
		plan:             reviewRunPlan(t, []domain.Role{domain.RoleLogic}),
	}
	authority.plan.Ceilings = review.DefaultHarnessCeilings()
	service := serviceForLifecycle(t, &calls, capture, &serviceAuthorityFactory{calls: &calls, authority: authority})
	service.dependencies.IDs = &recoveryFailureIDs{serviceIDs: serviceIDs{calls: &calls}}
	diagnostics := &serviceDiagnosticFactory{calls: &calls}
	service.dependencies.Diagnostics = diagnostics
	publisher := &recoveryFailurePublisher{servicePublisher: servicePublisher{calls: &calls}}
	service.dependencies.Publication = publisher
	return &recoveryFailureHarness{
		calls:       &calls,
		lease:       lease,
		capture:     capture,
		provider:    provider,
		authority:   authority,
		service:     service,
		diagnostics: diagnostics,
		publisher:   publisher,
	}
}

type recoveryFailureIDs struct{ serviceIDs }

func (*recoveryFailureIDs) NewAttemptID(time.Time) (domain.AttemptID, error) {
	return domain.ParseAttemptID("a_019f5a09-5eec-7001-8001-000000000003")
}
func (*recoveryFailureIDs) NewRoleTaskID(time.Time) (string, error) {
	return "rt_019f5a09-5eec-7001-8001-000000000004", nil
}
func (*recoveryFailureIDs) NewSourceInvocationID(time.Time) (string, error) {
	return "i_019f5a09-5eec-7001-8001-000000000005", nil
}
func (*recoveryFailureIDs) NewExecutionInvocationID(time.Time) (string, error) {
	return "019f5a09-5eec-7001-8001-000000000006", nil
}

type recoveryFailureProvider struct {
	calls  int
	err    error
	cancel context.CancelFunc
}

func (provider *recoveryFailureProvider) Observe(context.Context, ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	provider.calls++
	if provider.cancel != nil {
		provider.cancel()
	}
	if provider.err == nil {
		return ports.ProviderExecutionObservation{}, context.Canceled
	}
	return ports.ProviderExecutionObservation{}, provider.err
}

type recoveryFailureAuthority struct {
	serviceAuthority
	provider *recoveryFailureProvider
	plan     ExecutionPlan
}

func (authority *recoveryFailureAuthority) Provider() ports.ObservedReviewProvider {
	return authority.provider
}
func (authority *recoveryFailureAuthority) Planner() ExecutionPlanner { return authority }
func (authority *recoveryFailureAuthority) Plan(context.Context, PlanningRequest) (ExecutionPlan, error) {
	return authority.plan, nil
}

type recoveryFailurePublisher struct {
	servicePublisher
	err     error
	writes  int
	checked int
	check   func(context.Context)
}

func (publisher *recoveryFailurePublisher) PersistFailedRunRecovery(ctx context.Context, _ ports.AnchoredRoot, _ recovery.Prepared, _ ports.WorkspaceTerminalReceipt) (domain.SourceReference, error) {
	publisher.writes++
	if publisher.check != nil {
		publisher.checked++
		publisher.check(ctx)
	}
	return domain.SourceReference{}, publisher.err
}
