package reviewrun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestWorkspaceAbortReasonPreservesStageAndOverridesSecurityAndCancellation(t *testing.T) {
	security, err := domain.NewFailure("review.provider", domain.FailureSecurityPolicy, "packet rejected", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := workspaceAbortReason(security, ports.WorkspaceAbortExecutionFailure); got != ports.WorkspaceAbortSecurityViolation {
		t.Fatalf("security abort reason = %q", got)
	}
	if got := workspaceAbortReason(context.Canceled, ports.WorkspaceAbortPlanningFailure); got != ports.WorkspaceAbortCancellation {
		t.Fatalf("cancellation abort reason = %q", got)
	}
	if got := workspaceAbortReason(errors.New("publication failed"), ports.WorkspaceAbortPublicationFailure); got != ports.WorkspaceAbortPublicationFailure {
		t.Fatalf("stage abort reason = %q", got)
	}
}

func TestCoordinatorNonPublishableFailurePrecedence(t *testing.T) {
	got := reduceNonPublishableCoordinatorFailures(
		domain.FailureCancelled,
		domain.FailureProviderUnavailable,
		domain.FailureArtifact,
		domain.FailureSecurityPolicy,
	)
	if got != domain.FailureSecurityPolicy {
		t.Fatalf("non-publishable failure = %q, want %q", got, domain.FailureSecurityPolicy)
	}
	if got := reduceNonPublishableCoordinatorFailures(domain.FailureTimeout, domain.FailureInvalidOutput); got != "" {
		t.Fatalf("publishable operational failures reduced to %q", got)
	}
}

func TestProviderExecutionFailuresAreSafeAndCanonical(t *testing.T) {
	security, err := NewProviderExecutionFailure(
		"zcode-default",
		domain.RoleSecurity,
		string(review.AttemptConditionUnrepairableProviderOutput),
		domain.FailureInvalidOutput,
	)
	if err != nil {
		t.Fatal(err)
	}
	logic, err := NewProviderExecutionFailure(
		"kimi-default",
		domain.RoleLogic,
		string(review.AttemptConditionInternalInvariant),
		domain.FailureInternal,
	)
	if err != nil {
		t.Fatal(err)
	}
	aggregate := NewProviderExecutionFailuresError([]ProviderExecutionFailure{security, logic})
	failures, ok := ProviderExecutionFailuresFromError(aggregate)
	if !ok || len(failures) != 2 || failures[0].ProviderInstance() != "kimi-default" ||
		failures[0].Role() != domain.RoleLogic || failures[0].FailureClass() != domain.FailureInternal ||
		failures[1].ProviderInstance() != "zcode-default" ||
		failures[1].Role() != domain.RoleSecurity || failures[1].FailureClass() != domain.FailureInvalidOutput {
		t.Fatalf("provider execution failures = %#v, present=%t", failures, ok)
	}
	if _, err := NewProviderExecutionFailure(
		"kimi-default",
		domain.RoleLogic,
		"provider-supplied free form text",
		domain.FailureSecurityPolicy,
	); err == nil {
		t.Fatal("free-form provider execution reason was accepted")
	}
}

func TestProviderExecutionFailurePreservesOnlySafeTimeoutFacts(t *testing.T) {
	facts, err := review.NewProviderTimeoutFacts(30*time.Minute, 30*time.Minute+125*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	failure, err := NewProviderExecutionFailureWithTimeoutFacts(
		"zcode-logic", domain.RoleLogic, string(review.AttemptConditionProviderTimeout), domain.FailureTimeout, facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := failure.ProviderTimeoutFacts()
	if !ok || got.ConfiguredTimeout() != 30*time.Minute || got.Elapsed() != 30*time.Minute+125*time.Millisecond {
		t.Fatalf("timeout facts = %#v/%t", got, ok)
	}
	if _, err := NewProviderExecutionFailureWithTimeoutFacts(
		"zcode-logic", domain.RoleLogic, string(review.AttemptConditionProviderOutputMissing), domain.FailureInvalidOutput, facts,
	); err == nil {
		t.Fatal("timeout facts were accepted for a non-timeout failure")
	}
}

func TestProviderLoginRequiredProvidersIncludeTerminalExecutionFacts(t *testing.T) {
	login, err := NewProviderExecutionFailure("zcode-default", domain.RoleSecurity, string(review.AttemptConditionLoginRequired), domain.FailureAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, err := NewProviderExecutionFailure("zcode-default", domain.RoleLogic, string(review.AttemptConditionCancelled), domain.FailureCancelled)
	if err != nil {
		t.Fatal(err)
	}
	providers, ok := ProviderLoginRequiredProvidersFromError(NewProviderExecutionFailuresError([]ProviderExecutionFailure{cancelled, login}))
	if !ok || len(providers) != 1 || providers[0] != "zcode-default" {
		t.Fatalf("execution login providers = %v, present=%t", providers, ok)
	}
}

func TestDefaultTemplateSetContainsProductionReviewRoles(t *testing.T) {
	templates, err := LoadDefaultTemplateSet(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range domain.FixedRoleOrder() {
		layer, ok := templates.RoleTemplate(role)
		if !ok || layer.ID() != "builtin:roles/"+string(role) || layer.Version() != "1" {
			t.Fatalf("template for %s = %#v, present=%t", role, layer, ok)
		}
	}
	if templates.Common().Version() != "1" || templates.ReviewRun().Version() != "1" || templates.JSONOutput().Version() != "1" || templates.Repair().Version() != "1" {
		t.Fatal("default template versions are not explicit")
	}
}

func TestProviderReviewWirePromptRetainsOptionalJSONNestedContract(t *testing.T) {
	t.Parallel()
	assetID, err := ports.ParseAssetID("sot:prompts/root-review/output-provider-review-wire.v1.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, raw, err := builtin.NewCatalog().Read(context.Background(), assetID)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[len(raw)-1] == '\n' {
		t.Fatalf("wire prompt trailing byte = %q, want non-empty without EOF LF", raw[len(raw)-1:])
	}
	text := string(raw)
	if !strings.Contains(text, "Markdown is the primary success form") ||
		!strings.Contains(text, "Optional exact JSON compatibility branch:") ||
		!strings.Contains(text, "Otherwise return Markdown only") {
		t.Fatal("wire prompt lost Markdown-primary / optional JSON branch framing")
	}
	for _, required := range []string{
		`schema_version: exactly "mulgae-provider-review-output.v1"`,
		"Top level: exactly schema_version, summary, completeness, limitations, findings.",
		"Each finding has exactly severity, title, description, evidence, recommendation, confidence.",
		"evidence: array of 1..20 objects; each has current and may include visual.",
		"current has exactly path, line_start, line_end, side, quote.",
		"side: exactly base, head, worktree, or index.",
		`quote: meaningful exact target bytes for that inclusive range, represented as a JSON string; include every selected line's terminating LF as \n when the target line has one, including the final selected line.`,
		"For artist findings, visual has path, sha256, and bbox with non-negative x and y plus positive width and height.",
		`Do not emit target_sha256, verification, source, any session/run/attempt/review/finding ID, role/provider identity, lifecycle/evidence state, verdict/coverage/CI/publication state, hashes, or any other field.`,
		`Mulgae injects target_sha256 and verification="claimed"`,
		"Before returning, silently perform this final output check:",
		"every evidence quote exactly matches the selected target lines and includes each terminating LF as \\n",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("optional JSON branch omitted nested requirement %q", required)
		}
	}
}

func TestRootReviewLayerProvenanceOrderAndRepair(t *testing.T) {
	templates, err := LoadDefaultTemplateSet(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	objective := prompt.NewObjective([]byte("@roadmap.md"))
	base, err := templates.ComposeRootReview(domain.RoleLogic, &objective)
	if err != nil {
		t.Fatal(err)
	}
	wantBase := []string{
		"builtin:review/common",
		"builtin:run/review",
		"builtin:roles/logic",
		"review:objective",
		"builtin:output/provider-review-wire",
	}
	assertLayerIDs(t, base, wantBase)
	repaired, err := templates.ComposeRootReviewRepair(base, validation.RepairPlan{})
	if err != nil {
		t.Fatal(err)
	}
	assertLayerIDs(t, repaired, append(wantBase, "builtin:repair/provider-review", "review:repair-plan"))
	if repaired.Version() != "1" || !bytes.Contains(repaired.Bytes(), []byte("Mulgae ROOT REVIEW REPAIR CONTRACT/1")) ||
		!bytes.Contains(repaired.Bytes(), []byte("Mulgae ROOT REVIEW REPAIR PLAN/1")) ||
		!bytes.Contains(repaired.Bytes(), []byte("provider-review wire v1")) ||
		bytes.Contains(repaired.Bytes(), []byte("provider-review wire v2")) {
		t.Fatalf("repair template retained a stale contract: version=%q", repaired.Version())
	}
}

func assertLayerIDs(t *testing.T, template prompt.TrustedTemplate, want []string) {
	t.Helper()
	got := template.TrustedLayerManifest()
	if len(got) != len(want) {
		t.Fatalf("layer count = %d, want %d", len(got), len(want))
	}
	for index, id := range want {
		if got[index].Ordinal() != index+1 || got[index].ID() != id {
			t.Fatalf("layer %d = ordinal=%d id=%q, want ordinal=%d id=%q",
				index, got[index].Ordinal(), got[index].ID(), index+1, id)
		}
	}
}

func TestImmutableReviewInputCopiesPayloads(t *testing.T) {
	objective := []byte("@roadmap.md")
	context := []byte("project")
	target, err := ports.NewCapturedReviewPatchTarget([]byte("patch"))
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewImmutableReviewInput(target, objective, true, context)
	if err != nil {
		t.Fatal(err)
	}
	objective[0], context[0] = 'x', 'x'
	if string(input.Objective()) != "@roadmap.md" || string(input.ProjectContext()) != "project" {
		t.Fatal("immutable input retained caller storage")
	}
}

type packetDetectorFake struct {
	detection   ports.ReviewInputDetection
	packet      []byte
	detectorErr error
}

func (fake *packetDetectorFake) DetectReviewInput(_ context.Context, channel ports.ReviewInputChannel, _ string, bytes []byte) (ports.ReviewInputDetection, error) {
	if channel != ports.ReviewInputPacket {
		return ports.ReviewInputDetection{}, errors.New("unexpected detector channel")
	}
	fake.packet = append([]byte(nil), bytes...)
	return fake.detection, fake.detectorErr
}

type observedProviderFake struct{ calls int }

func (fake *observedProviderFake) Observe(context.Context, ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	fake.calls++
	return ports.ProviderExecutionObservation{}, nil
}

func TestPacketScreeningProviderScreensInitialAndRepair(t *testing.T) {
	clean, err := ports.NewReviewInputDetection(ports.ReviewInputClean, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	detector := &packetDetectorFake{detection: clean}
	provider := &observedProviderFake{}
	screened := &packetScreeningProvider{provider: provider, detector: detector}
	for _, purpose := range []ports.ProviderInvocationPurpose{ports.ProviderInvocationInitial, ports.ProviderInvocationRepair} {
		if _, err := screened.Observe(context.Background(), screeningInvocation(t, purpose)); err != nil {
			t.Fatal(err)
		}
	}
	if provider.calls != 2 || string(detector.packet) != "complete provider packet" || screened.Blocked() {
		t.Fatal("clean provider packets were not screened and exposed exactly once")
	}
}

func TestPacketScreeningProviderBlocksBeforeProviderExposure(t *testing.T) {
	blocked, err := ports.NewReviewInputDetection(ports.ReviewInputBlocked, "credential", 1)
	if err != nil {
		t.Fatal(err)
	}
	provider := &observedProviderFake{}
	screened := &packetScreeningProvider{provider: provider, detector: &packetDetectorFake{detection: blocked}}
	if _, err := screened.Observe(context.Background(), screeningInvocation(t, ports.ProviderInvocationInitial)); err == nil || provider.calls != 0 || !screened.Blocked() {
		t.Fatal("blocked provider packet reached provider")
	}
}
func TestPacketScreeningProviderReportsDetectorFailureDistinctly(t *testing.T) {
	detectorErr := errors.New("detector unavailable")
	provider := &observedProviderFake{}
	screened := &packetScreeningProvider{
		provider: provider,
		detector: &packetDetectorFake{detectorErr: detectorErr},
	}
	_, err := screened.Observe(context.Background(), screeningInvocation(t, ports.ProviderInvocationInitial))
	if !errors.Is(err, detectorErr) || screened.Blocked() || !errors.Is(screened.DetectorError(), detectorErr) || provider.calls != 0 {
		t.Fatal("detector failure was treated as packet rejection or exposed the packet")
	}
}

func TestPacketScreeningProviderDoesNotRetainContextTerminationAsDetectorFailure(t *testing.T) {
	for _, detectorErr := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(detectorErr.Error(), func(t *testing.T) {
			provider := &observedProviderFake{}
			screened := &packetScreeningProvider{
				provider: provider,
				detector: &packetDetectorFake{detectorErr: detectorErr},
			}
			_, err := screened.Observe(context.Background(), screeningInvocation(t, ports.ProviderInvocationInitial))
			if !errors.Is(err, detectorErr) || screened.Blocked() || screened.DetectorError() != nil || provider.calls != 0 {
				t.Fatal("context termination was retained as a detector infrastructure failure")
			}
		})
	}
}

func screeningInvocation(t *testing.T, purpose ports.ProviderInvocationPurpose) ports.ProviderInvocation {
	t.Helper()
	attempt, err := domain.ParseAttemptID("a_019f5a09-5eec-7001-8001-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	packetBytes := []byte("complete provider packet")
	packet, err := ports.NewProviderPacket(packetBytes, prompt.CompleteStdinSHA256(packetBytes))
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := ports.NewProviderInvocationWithPacket(domain.RoleLogic, "fake.logic", attempt, purpose, packet, "i_019f5a09-5eec-7001-8001-000000000002", "019f5a09-5eec-7001-8001-000000000003")
	if err != nil {
		t.Fatal(err)
	}
	return invocation
}
func TestServiceExecuteWorkspaceLeaseBeforeBuildConstructionFailureAbortsLease(t *testing.T) {
	calls := []string{}
	lease := newServiceLease(t, &calls)
	capture := &serviceCapture{captured: serviceCapturedChanged(t, lease)}
	service := serviceForLifecycle(t, &calls, capture, &serviceAuthorityFactory{calls: &calls})
	service.dependencies.Build = BuildIdentity{}

	_, err := service.Execute(context.Background(), serviceRequest(t, capture))
	if err == nil {
		t.Fatal("Execute() succeeded with an invalid build identity")
	}
	assertServiceCalls(t, calls, []string{"capture", "abort"})
	if !lease.aborted || !lease.abort.TerminalReceipt().NoNamespaces() {
		t.Fatal("build construction failure did not abort the captured workspace with empty provider terminal evidence")
	}
}

func TestServiceExecuteMalformedAuthorityDrainsProviderAndWorkspace(t *testing.T) {
	calls := []string{}
	lease := newServiceLease(t, &calls)
	providerFailure := errors.New("provider terminal cleanup failed")
	workspaceFailure := errors.New("workspace abort failed")
	lease.abortErr = workspaceFailure
	authority := &serviceAuthority{
		calls:                &calls,
		terminal:             serviceQualifiedTerminal(t),
		drainErrors:          []error{providerFailure, providerFailure},
		drainTerminalOnError: true,
		invalidProvider:      true,
	}
	capture := &serviceCapture{captured: serviceCapturedChanged(t, lease)}
	service := serviceForLifecycle(t, &calls, capture, &serviceAuthorityFactory{
		calls:     &calls,
		authority: authority,
	})

	_, err := service.Execute(context.Background(), serviceRequest(t, capture))
	if !errors.Is(err, providerFailure) || !errors.Is(err, workspaceFailure) {
		t.Fatalf("Execute() error = %v, want joined provider and workspace cleanup failures", err)
	}
	assertServiceCalls(t, calls, []string{"capture", "session", "run", "authority", "drain", "drain", "abort"})
	state, ok := CleanupStateFromError(err)
	if !ok || state.ProviderOwner() != authority || state.WorkspaceLease() != lease || state.ProviderDrained() || state.WorkspaceDrained() {
		t.Fatal("malformed authority cleanup did not retain both retry authorities")
	}
}
func TestServiceExecuteConstructionFailureRetainsOwnerForCleanupRetry(t *testing.T) {
	calls := []string{}
	lease := newServiceLease(t, &calls)
	constructionFailure := errors.New("authority construction failed")
	firstDrainFailure := errors.New("first terminal drain failed")
	authority := &serviceAuthority{
		calls:       &calls,
		terminal:    serviceQualifiedTerminal(t),
		drainErrors: []error{firstDrainFailure, firstDrainFailure, nil},
	}
	capture := &serviceCapture{captured: serviceCapturedChanged(t, lease)}
	service := serviceForLifecycle(t, &calls, capture, &serviceAuthorityFactory{
		calls:     &calls,
		authority: authority,
		err: &terminalDrainCleanupError{
			cause: constructionFailure,
			owner: authority,
		},
	})

	_, err := service.Execute(context.Background(), serviceRequest(t, capture))
	if !errors.Is(err, constructionFailure) || !errors.Is(err, firstDrainFailure) {
		t.Fatalf("Execute() error = %v, want construction and first drain failures", err)
	}
	assertServiceCalls(t, calls, []string{"capture", "session", "run", "authority", "drain", "drain"})
	state, ok := CleanupStateFromError(err)
	if !ok || state.ProviderOwner() != authority || state.WorkspaceLease() != lease || state.ProviderDrained() || state.WorkspaceDrained() {
		t.Fatal("construction failure did not retain the exact cleanup authorities")
	}

	if err := state.DrainAndAbort(context.Background(), ports.WorkspaceAbortPlanningFailure); err != nil {
		t.Fatalf("cleanup retry = %v", err)
	}
	assertServiceCalls(t, calls, []string{"capture", "session", "run", "authority", "drain", "drain", "drain", "abort"})
	if !state.ProviderDrained() || !state.WorkspaceDrained() || lease.abort.WorkspaceSnapshotIdentity() != lease.identity {
		t.Fatal("cleanup retry did not drain the retained provider then abort the captured workspace identity")
	}
}

func TestServiceExecuteRetriesTerminalDrainBeforeAbort(t *testing.T) {
	calls := []string{}
	lease := newServiceLease(t, &calls)
	terminal := serviceQualifiedTerminal(t)
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), serviceContextKey{}, "preserved"))
	defer cancel()
	capture := &serviceCapture{captured: serviceCapturedChanged(t, lease)}
	authority := &serviceAuthority{
		calls:       &calls,
		terminal:    terminal,
		drainErrors: []error{errors.New("first drain failed"), nil},
		cancelPlan:  cancel,
		drainCheck: func(ctx context.Context) {
			if _, bounded := ctx.Deadline(); !bounded {
				t.Error("terminal drain context is unbounded")
			}
			if ctx.Err() != nil {
				t.Errorf("terminal drain inherited cancellation: %v", ctx.Err())
			}
			if value := ctx.Value(serviceContextKey{}); value != "preserved" {
				t.Errorf("terminal drain lost parent value: %v", value)
			}
		},
	}
	service := serviceForLifecycle(t, &calls, capture, &serviceAuthorityFactory{
		calls:     &calls,
		authority: authority,
	})
	diagnostics := &serviceDiagnosticFactory{calls: &calls}
	service.dependencies.Diagnostics = diagnostics
	_, err := service.Execute(parent, serviceRequest(t, capture))
	if err == nil {
		t.Fatal("Execute() succeeded after planning failure")
	}
	assertServiceCalls(t, calls, []string{"capture", "session", "run", "sink", "authority", "plan", "drain", "drain", "abort"})
	if !providerTerminalMatches(lease.abort.TerminalReceipt(), terminal.ProviderRunTerminalReceipt()) {
		t.Fatal("abort did not retain the retried terminal aggregate")
	}
	wantCleanup := []domain.RuntimeDiagnosticEventCode{
		domain.DiagnosticNamespaceDrainStarted, domain.DiagnosticNamespaceDrained,
		domain.DiagnosticWorkspaceCleanupStarted, domain.DiagnosticWorkspaceCleanupCompleted,
	}
	position := 0
	for _, event := range diagnostics.events {
		if position < len(wantCleanup) && event == wantCleanup[position] {
			position++
		}
	}
	if position != len(wantCleanup) {
		t.Fatalf("cancelled cleanup diagnostics = %v, missing %v", diagnostics.events, wantCleanup[position:])
	}
	if len(diagnostics.finalizeRequests) != 1 || diagnostics.finalizeRequests[0].State() != domain.RunCancelled {
		t.Fatalf("cancelled finalize requests = %#v", diagnostics.finalizeRequests)
	}
}

func TestServiceExecuteRetainsCleanupOwnerWhenTerminalDrainPersists(t *testing.T) {
	calls := []string{}
	lease := newServiceLease(t, &calls)
	capture := &serviceCapture{captured: serviceCapturedChanged(t, lease)}
	authority := &serviceAuthority{calls: &calls, drainErrors: []error{errors.New("first"), errors.New("second")}}
	service := serviceForLifecycle(t, &calls, capture, &serviceAuthorityFactory{
		calls:     &calls,
		authority: authority,
	})
	_, err := service.Execute(context.Background(), serviceRequest(t, capture))
	if err == nil {
		t.Fatal("Execute() succeeded with persistent terminal drain failure")
	}
	assertServiceCalls(t, calls, []string{"capture", "session", "run", "authority", "plan", "drain", "drain"})
	if lease.aborted {
		t.Fatal("persistent drain failure aborted workspace without terminal proof")
	}
	owner, ok := CleanupOwnerFromError(err)
	if !ok || owner != authority {
		t.Fatalf("cleanup owner = %#v, %t, want retained authority", owner, ok)
	}
	partial, ok := PartialProviderRunTerminalReceiptFromError(err)
	if !ok || partial.Valid() || partial.NoNamespaces() {
		t.Fatalf("partial terminal = %#v, %t, want incomplete non-empty-proof evidence", partial, ok)
	}
}
func TestReviewRunCleanupTracksMixedOutcomesAndPreservesRetryAuthority(t *testing.T) {
	terminal := serviceQualifiedTerminal(t)
	providerFailure := errors.New("provider cleanup failed")
	workspaceFailure := errors.New("workspace cleanup failed")

	t.Run("provider clean workspace failed", func(t *testing.T) {
		calls := []string{}
		lease := newServiceLease(t, &calls)
		lease.abortErr = workspaceFailure
		cleanup := newReviewRunCleanup(lease)
		cleanup.setProviderOwner(&serviceAuthority{calls: &calls, terminal: terminal})
		err := cleanup.DrainAndAbort(context.Background(), ports.WorkspaceAbortExecutionFailure)
		if !errors.Is(err, workspaceFailure) || !cleanup.ProviderDrained() || cleanup.WorkspaceDrained() {
			t.Fatal("cleanup did not retain workspace-only failure")
		}
		state, ok := CleanupStateFromError(err)
		if !ok || state != cleanup || state.ProviderOwner() == nil || state.WorkspaceLease() != lease {
			t.Fatal("cleanup did not retain exact retry authorities")
		}
	})

	t.Run("workspace clean provider failed", func(t *testing.T) {
		calls := []string{}
		lease := newServiceLease(t, &calls)
		cleanup := &ReviewRunCleanup{
			provider:         &serviceAuthority{calls: &calls, drainErrors: []error{providerFailure, providerFailure}},
			workspace:        lease,
			terminal:         terminal.ProviderRunTerminalReceipt(),
			workspaceDrained: true,
		}
		err := cleanup.DrainAndAbort(context.Background(), ports.WorkspaceAbortExecutionFailure)
		if !errors.Is(err, providerFailure) || cleanup.ProviderDrained() || !cleanup.WorkspaceDrained() {
			t.Fatal("cleanup did not retain provider-only failure")
		}
	})

	t.Run("both failed", func(t *testing.T) {
		calls := []string{}
		lease := newServiceLease(t, &calls)
		lease.abortErr = workspaceFailure
		cleanup := &ReviewRunCleanup{
			provider:  &serviceAuthority{calls: &calls, terminal: terminal, drainErrors: []error{providerFailure, providerFailure}, drainTerminalOnError: true},
			workspace: lease,
			terminal:  terminal.ProviderRunTerminalReceipt(),
		}
		err := cleanup.DrainAndAbort(context.Background(), ports.WorkspaceAbortExecutionFailure)
		if !errors.Is(err, providerFailure) || !errors.Is(err, workspaceFailure) || cleanup.ProviderDrained() || cleanup.WorkspaceDrained() {
			t.Fatal("cleanup did not join unresolved provider and workspace failures")
		}
	})

	t.Run("retry and both clean", func(t *testing.T) {
		calls := []string{}
		lease := newServiceLease(t, &calls)
		lease.abortErr = workspaceFailure
		cleanup := newReviewRunCleanup(lease)
		cleanup.setProviderOwner(&serviceAuthority{calls: &calls, terminal: terminal})
		if err := cleanup.DrainAndAbort(context.Background(), ports.WorkspaceAbortExecutionFailure); !errors.Is(err, workspaceFailure) {
			t.Fatal("initial cleanup did not report workspace failure")
		}
		lease.abortErr = nil
		if err := cleanup.DrainAndAbort(context.Background(), ports.WorkspaceAbortExecutionFailure); err != nil || !cleanup.ProviderDrained() || !cleanup.WorkspaceDrained() {
			t.Fatalf("retry cleanup = %v, provider=%t workspace=%t", err, cleanup.ProviderDrained(), cleanup.WorkspaceDrained())
		}
	})
}

func TestServiceExecuteNoChangePreReleaseFailureAbortsWithEmptyTerminal(t *testing.T) {
	calls := []string{}
	lease := newServiceLease(t, &calls)
	ids := &serviceIDs{calls: &calls, runErr: errors.New("run ID unavailable")}
	capture := &serviceCapture{captured: serviceCapturedNoChange(t, lease)}
	service := serviceForLifecycle(t, &calls, capture, &serviceAuthorityFactory{calls: &calls})
	service.dependencies.IDs = ids
	_, err := service.Execute(context.Background(), serviceRequest(t, capture))
	if err == nil {
		t.Fatal("Execute() succeeded with no-change pre-release failure")
	}
	assertServiceCalls(t, calls, []string{"capture", "session", "run", "abort"})
	if !lease.abort.TerminalReceipt().NoNamespaces() {
		t.Fatal("no-change abort did not use the exact empty provider terminal aggregate")
	}
}

func TestIssueRootRunIdentityPreservesSuppliedSession(t *testing.T) {
	calls := []string{}
	supplied, err := domain.ParseSessionID("s_019f5a09-5eec-7001-8001-000000000099")
	if err != nil {
		t.Fatal(err)
	}
	selection, err := NewRunSelection([]domain.Role{domain.RoleLogic, domain.RoleSecurity}, &supplied)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{dependencies: Dependencies{Clock: serviceClock{}, IDs: &serviceIDs{calls: &calls}}}
	identity, err := service.issueRootRunIdentity(selection)
	if err != nil {
		t.Fatal(err)
	}
	if identity.sessionID != supplied || identity.runID.String() == "" || identity.startedAt.IsZero() {
		t.Fatalf("identity = %#v, want supplied session and issued run", identity)
	}
	assertServiceCalls(t, calls, []string{"run"})
}

func TestServiceExecuteOpensDiagnosticsBeforeQualification(t *testing.T) {
	calls := []string{}
	lease := newServiceLease(t, &calls)
	capture := &serviceCapture{captured: serviceCapturedChanged(t, lease)}
	authority := &serviceAuthority{calls: &calls, terminal: serviceQualifiedTerminal(t)}
	service := serviceForLifecycle(t, &calls, capture, &serviceAuthorityFactory{calls: &calls, authority: authority})
	diagnostics := &serviceDiagnosticFactory{calls: &calls}
	service.dependencies.Diagnostics = diagnostics

	_, err := service.Execute(context.Background(), serviceRequest(t, capture))
	if err == nil {
		t.Fatal("Execute() succeeded after planning failure")
	}
	assertServiceCalls(t, calls, []string{"capture", "session", "run", "sink", "authority", "plan", "drain", "abort"})
	want := []domain.RuntimeDiagnosticEventCode{
		domain.DiagnosticCommandAccepted, domain.DiagnosticRuntimeOpened, domain.DiagnosticSessionCreated, domain.DiagnosticRunCreated,
		domain.DiagnosticQualificationStarted, domain.DiagnosticQualificationCandidateChecked,
		domain.DiagnosticNamespaceDrainStarted, domain.DiagnosticNamespaceDrained,
		domain.DiagnosticWorkspaceCleanupStarted, domain.DiagnosticWorkspaceCleanupCompleted,
	}
	if len(diagnostics.events) != len(want) {
		t.Fatalf("initial diagnostic events = %v", diagnostics.events)
	}
	for index := range want {
		if diagnostics.events[index] != want[index] {
			t.Fatalf("initial diagnostic events = %v, want %v", diagnostics.events, want)
		}
	}
}

func TestServiceExecuteDiagnosticOpenFailurePreventsQualification(t *testing.T) {
	calls := []string{}
	lease := newServiceLease(t, &calls)
	capture := &serviceCapture{captured: serviceCapturedChanged(t, lease)}
	service := serviceForLifecycle(t, &calls, capture, &serviceAuthorityFactory{calls: &calls})
	service.dependencies.Diagnostics = &serviceDiagnosticFactory{calls: &calls, openErr: errors.New("injected open failure")}

	_, err := service.Execute(context.Background(), serviceRequest(t, capture))
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact {
		t.Fatalf("open failure = %v, want typed artifact failure", err)
	}
	assertServiceCalls(t, calls, []string{"capture", "session", "run", "sink", "abort"})
	if _, ok := RuntimeDiagnosticURIFromError(err); ok {
		t.Fatal("failed diagnostic open exposed a dangling URI")
	}
}

func TestServiceExecuteDiagnosticFinalizeFailureHasNoURI(t *testing.T) {
	calls := []string{}
	lease := newServiceLease(t, &calls)
	capture := &serviceCapture{captured: serviceCapturedChanged(t, lease)}
	authority := &serviceAuthority{calls: &calls, terminal: serviceQualifiedTerminal(t)}
	service := serviceForLifecycle(t, &calls, capture, &serviceAuthorityFactory{calls: &calls, authority: authority})
	service.dependencies.Diagnostics = &serviceDiagnosticFactory{calls: &calls, finalizeErr: errors.New("injected finalize failure")}

	_, err := service.Execute(context.Background(), serviceRequest(t, capture))
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact {
		t.Fatalf("finalize failure = %v, want typed artifact failure", err)
	}
	if _, ok := RuntimeDiagnosticURIFromError(err); ok {
		t.Fatal("failed diagnostic finalize exposed a dangling URI")
	}
}

func TestServiceExecuteFinalizesLoginRequiredAfterCleanup(t *testing.T) {
	calls := []string{}
	lease := newServiceLease(t, &calls)
	capture := &serviceCapture{captured: serviceCapturedChanged(t, lease)}
	authority := &serviceAuthority{calls: &calls, terminal: serviceQualifiedTerminal(t)}
	failure, err := domain.NewFailure("qualification", domain.FailureAuthentication, "provider login required", ports.ErrProviderLoginRequired)
	if err != nil {
		t.Fatal(err)
	}
	loginErr := newProviderLoginRequiredError([]string{"agy"}, failure)
	service := serviceForLifecycle(t, &calls, capture, &serviceAuthorityFactory{calls: &calls, authority: authority, err: loginErr})
	diagnostics := &serviceDiagnosticFactory{calls: &calls}
	service.dependencies.Diagnostics = diagnostics

	_, err = service.Execute(context.Background(), serviceRequest(t, capture))
	providers, loginRequired := ProviderLoginRequiredProvidersFromError(err)
	if !loginRequired || len(providers) != 1 || providers[0] != "agy" {
		t.Fatalf("login-required failure = %v, providers %v", err, providers)
	}
	if uri, ok := RuntimeDiagnosticURIFromError(err); !ok || uri.String() != ".mulgae/diagnostics/s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002" {
		t.Fatal("login-required failure did not expose installed diagnostics")
	}
	if len(diagnostics.finalizeRequests) != 1 || diagnostics.finalizeRequests[0].State() != domain.RunFailed || diagnostics.finalizeRequests[0].Cause() != domain.DiagnosticCauseLoginRequired {
		t.Fatalf("login-required finalize requests = %#v", diagnostics.finalizeRequests)
	}
	want := []domain.RuntimeDiagnosticEventCode{
		domain.DiagnosticQualificationStarted, domain.DiagnosticQualificationRejected,
		domain.DiagnosticNamespaceDrainStarted, domain.DiagnosticNamespaceDrained,
		domain.DiagnosticWorkspaceCleanupStarted, domain.DiagnosticWorkspaceCleanupCompleted,
	}
	position := 0
	for _, event := range diagnostics.events {
		if position < len(want) && event == want[position] {
			position++
		}
	}
	if position != len(want) {
		t.Fatalf("login-required diagnostics = %v, missing %v", diagnostics.events, want[position:])
	}
}

func TestServiceExecuteRejectsNoChangeReleaseReceiptMismatch(t *testing.T) {
	calls := []string{}
	lease := newServiceLease(t, &calls)
	lease.mismatchRelease = true
	capture := &serviceCapture{captured: serviceCapturedNoChange(t, lease)}
	service := serviceForLifecycle(t, &calls, capture, &serviceAuthorityFactory{calls: &calls})
	_, err := service.Execute(context.Background(), serviceRequest(t, capture))
	if err == nil {
		t.Fatal("Execute() accepted mismatched no-change release receipt")
	}
	assertServiceCalls(t, calls, []string{"capture", "session", "run", "release"})
	if lease.aborted {
		t.Fatal("release mismatch issued a second abort after terminal release")
	}
}
func TestServiceExecuteNoChangePublicationFailureDoesNotAbortAfterRelease(t *testing.T) {
	calls := []string{}
	lease := newServiceLease(t, &calls)
	capture := &serviceCapture{captured: serviceCapturedNoChange(t, lease)}
	service := serviceForLifecycle(t, &calls, capture, &serviceAuthorityFactory{calls: &calls})
	_, err := service.Execute(context.Background(), serviceRequest(t, capture))
	if err == nil {
		t.Fatal("Execute() succeeded when publication failed")
	}
	assertServiceCalls(t, calls, []string{"capture", "session", "run", "release", "publish"})
	if lease.aborted {
		t.Fatal("publication failure issued a second abort after terminal release")
	}
}

func TestNoChangeObjectiveDigestDistinguishesAbsentAndPresentEmpty(t *testing.T) {
	target := serviceNoChangeTarget(t)
	absent, err := NewImmutableReviewInput(target, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := NewImmutableReviewInput(target, []byte{}, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if noChangeObjectiveDigest(absent) != "" || noChangeObjectiveDigest(empty) == "" {
		t.Fatal("objective provenance did not distinguish absence from present empty input")
	}
}

type serviceContextKey struct{}
type serviceCapture struct{ captured CapturedRunInput }

func (capture *serviceCapture) Capture(context.Context, Request) (CapturedRunInput, error) {
	serviceCalls(capture.captured.WorkspaceLease(), "capture")
	return capture.captured, nil
}

type serviceClock struct{}

func (serviceClock) Now() time.Time { return time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC) }

type serviceIDs struct {
	calls  *[]string
	runErr error
}

func (ids *serviceIDs) NewSessionID(time.Time) (domain.SessionID, error) {
	if ids.calls != nil {
		*ids.calls = append(*ids.calls, "session")
	}
	id, _ := domain.ParseSessionID("s_019f5a09-5eec-7001-8001-000000000001")
	return id, nil
}
func (ids *serviceIDs) NewRunID(time.Time) (domain.RunID, error) {
	if ids.calls != nil {
		*ids.calls = append(*ids.calls, "run")
	}
	if ids.runErr != nil {
		return domain.RunID{}, ids.runErr
	}
	id, _ := domain.ParseRunID("r_019f5a09-5eec-7001-8001-000000000002")
	return id, nil
}
func (*serviceIDs) NewAttemptID(time.Time) (domain.AttemptID, error) {
	return domain.AttemptID{}, errors.New("unexpected attempt")
}
func (*serviceIDs) NewRoleTaskID(time.Time) (string, error) {
	return "", errors.New("unexpected role task")
}
func (*serviceIDs) NewSourceInvocationID(time.Time) (string, error) {
	return "", errors.New("unexpected source invocation")
}
func (*serviceIDs) NewExecutionInvocationID(time.Time) (string, error) {
	return "", errors.New("unexpected execution invocation")
}

type serviceAuthorityFactory struct {
	calls     *[]string
	authority RunAuthority
	err       error
}

type serviceDiagnosticFactory struct {
	calls            *[]string
	openErr          error
	finalizeErr      error
	events           []domain.RuntimeDiagnosticEventCode
	finalizeRequests []ports.RuntimeDiagnosticFinalizeRequest
}

func (factory *serviceDiagnosticFactory) Open(_ context.Context, request ports.RuntimeDiagnosticOpenRequest) (ports.RuntimeDiagnosticSink, error) {
	*factory.calls = append(*factory.calls, "sink")
	if factory.openErr != nil {
		return nil, factory.openErr
	}
	sink, err := ports.NewInMemoryRuntimeDiagnosticSink(request)
	if err != nil {
		return nil, err
	}
	return &serviceDiagnosticSink{RuntimeDiagnosticSink: sink, factory: factory}, nil
}

type serviceDiagnosticSink struct {
	ports.RuntimeDiagnosticSink
	factory *serviceDiagnosticFactory
}

func (sink *serviceDiagnosticSink) Emit(ctx context.Context, draft domain.RuntimeDiagnosticEventDraft) (domain.RuntimeDiagnosticEvent, error) {
	sink.factory.events = append(sink.factory.events, draft.Input().Event)
	return sink.RuntimeDiagnosticSink.Emit(ctx, draft)
}

func (sink *serviceDiagnosticSink) Finalize(ctx context.Context, request ports.RuntimeDiagnosticFinalizeRequest) (ports.RuntimeDiagnosticFinalizeResult, error) {
	sink.factory.finalizeRequests = append(sink.factory.finalizeRequests, request)
	if sink.factory.finalizeErr != nil {
		return ports.RuntimeDiagnosticFinalizeResult{}, sink.factory.finalizeErr
	}
	return sink.RuntimeDiagnosticSink.Finalize(ctx, request)
}

func (factory *serviceAuthorityFactory) NewQualifiedRun(context.Context, CapturedRunInput, RunSelection) (RunAuthority, error) {
	*factory.calls = append(*factory.calls, "authority")
	return factory.authority, factory.err
}

type serviceAuthority struct {
	calls                *[]string
	terminal             QualifiedRunTerminalReceipt
	drainErrors          []error
	drains               int
	cancelPlan           func()
	drainCheck           func(context.Context)
	drainTerminalOnError bool
	invalidProvider      bool
}

func (authority *serviceAuthority) Provider() ports.ObservedReviewProvider {
	if authority.invalidProvider {
		return nil
	}
	return &observedProviderFake{}
}
func (authority *serviceAuthority) Planner() ExecutionPlanner {
	return servicePlanner{calls: authority.calls, cancel: authority.cancelPlan}
}
func (authority *serviceAuthority) BuildIdentity() BuildIdentity {
	return BuildIdentity{Product: "mulgae", Version: "1.0.0", Module: "github.com/irootkernel/mulgae", VCSRevision: "abc123"}
}
func (authority *serviceAuthority) DrainTerminal(ctx context.Context) (QualifiedRunTerminalReceipt, error) {
	*authority.calls = append(*authority.calls, "drain")
	if authority.drainCheck != nil {
		authority.drainCheck(ctx)
	}
	index := authority.drains
	authority.drains++
	if index < len(authority.drainErrors) && authority.drainErrors[index] != nil {
		if authority.drainTerminalOnError {
			return authority.terminal, authority.drainErrors[index]
		}
		return QualifiedRunTerminalReceipt{}, authority.drainErrors[index]
	}
	return authority.terminal, nil
}

type servicePlanner struct {
	calls  *[]string
	cancel func()
}

func (planner servicePlanner) Plan(context.Context, PlanningRequest) (ExecutionPlan, error) {
	*planner.calls = append(*planner.calls, "plan")
	if planner.cancel != nil {
		planner.cancel()
	}
	return ExecutionPlan{}, errors.New("planning failed")
}

type serviceLease struct {
	identity        ports.WorkspaceSnapshotIdentity
	receipt         ports.WorkspaceSnapshotReceipt
	release         ports.WorkspaceTerminalRelease
	calls           *[]string
	abort           ports.WorkspaceAbortEvidence
	aborted         bool
	abortErr        error
	mismatchRelease bool
}

func serviceCalls(lease ports.WorkspaceSnapshotLease, call string) {
	if fake, ok := lease.(*serviceLease); ok {
		*fake.calls = append(*fake.calls, call)
	}
}
func (lease *serviceLease) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return lease.identity
}
func (*serviceLease) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	return nil, errors.New("unexpected workspace revalidation")
}
func (lease *serviceLease) Receipt() ports.WorkspaceSnapshotReceipt { return lease.receipt }
func (lease *serviceLease) Release(evidence ports.WorkspaceCompletionEvidence) (ports.WorkspaceTerminalReceipt, error) {
	if lease.mismatchRelease {
		*lease.calls = append(*lease.calls, "release")
		return ports.WorkspaceTerminalReceipt{}, nil
	}
	return lease.release(evidence)
}
func (lease *serviceLease) Abort(evidence ports.WorkspaceAbortEvidence) error {
	*lease.calls = append(*lease.calls, "abort")
	lease.abort, lease.aborted = evidence, true
	return lease.abortErr
}

type serviceReader struct{}

func (serviceReader) ReadImmutableTarget(context.Context, string, evidence.Side, ports.SafeRelativePath) (evidence.ImmutableTargetAvailability, []byte, error) {
	return evidence.ImmutableTargetUnavailable, nil, errors.New("unexpected target read")
}

func serviceForLifecycle(t *testing.T, calls *[]string, capture ImmutableInputSource, factory RunAuthorityFactory) *Service {
	t.Helper()
	service, err := NewService(Dependencies{
		Clock: serviceClock{}, IDs: &serviceIDs{calls: calls}, Build: BuildIdentity{Product: "mulgae", Version: "1.0.0", Module: "github.com/irootkernel/mulgae", VCSRevision: "abc123"},
		RunAuthorityFactory: factory, Validator: &validation.ReviewValidator{}, Publication: servicePublisher{calls: calls}, Templates: mustServiceTemplates(t),
		Diagnostics: ports.NewInMemoryRuntimeDiagnosticSinkFactory(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func mustServiceTemplates(t *testing.T) review.TemplateSet {
	t.Helper()
	templates, err := LoadDefaultTemplateSet(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	return templates
}

type servicePublisher struct{ calls *[]string }

func (publisher servicePublisher) PublishNext(context.Context, ports.AnchoredRoot, publication.PreparedCandidate) (publication.PublicationResult, error) {
	*publisher.calls = append(*publisher.calls, "publish")
	return publication.PublicationResult{}, errors.New("publication failed")
}

func serviceRequest(t *testing.T, inputSource ImmutableInputSource) Request {
	t.Helper()
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	selection, err := NewRunSelection([]domain.Role{domain.RoleLogic}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return Request{InputSource: inputSource, ProjectRoot: root, ArtifactRoot: root, Selection: selection}
}

func serviceCapturedChanged(t *testing.T, lease ports.WorkspaceSnapshotLease) CapturedRunInput {
	t.Helper()
	input, err := NewImmutableReviewInput(reviewRunPatchTarget(t), nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := NewCapturedRunInput(input, lease, serviceReader{}, &packetDetectorFake{})
	if err != nil {
		t.Fatal(err)
	}
	return captured
}

func serviceCapturedNoChange(t *testing.T, lease ports.WorkspaceSnapshotLease) CapturedRunInput {
	t.Helper()
	input, err := NewImmutableReviewInput(serviceNoChangeTarget(t), nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := NewCapturedRunInput(input, lease, nil)
	if err != nil {
		t.Fatal(err)
	}
	return captured
}

func serviceNoChangeTarget(t *testing.T) ports.CapturedReviewTarget {
	t.Helper()
	target, err := ports.NewCapturedReviewGitTarget("repository:test", reviewRunObjectID(t, "1"), reviewRunObjectID(t, "2"), reviewRunObjectID(t, "3"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func newServiceLease(t *testing.T, calls *[]string) *serviceLease {
	t.Helper()
	const manifest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	identity, err := ports.NewWorkspaceSnapshotIdentity("/private/snapshot", "snapshot-0123456789abcdef0123456789abcdef", manifest, "policy", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := ports.NewWorkspaceSnapshotReceipt("/private/snapshot", "snapshot-0123456789abcdef0123456789abcdef", manifest, "policy", 1, 2, 3, 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	lease := &serviceLease{identity: identity, receipt: receipt, calls: calls}
	acquired, err := ports.AcquireWorkspaceSnapshotLease(context.Background(), func(_ context.Context, binding ports.WorkspaceTerminalBinding) (ports.WorkspaceSnapshotLease, error) {
		release, err := binding.Bind(identity, func(ports.WorkspaceCompletionEvidence) error {
			*lease.calls = append(*lease.calls, "release")
			return nil
		})
		if err != nil {
			return nil, err
		}
		lease.release = release
		return lease, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return acquired.(*serviceLease)
}

func serviceQualifiedTerminal(t *testing.T) QualifiedRunTerminalReceipt {
	t.Helper()
	namespace := acquiredProviderNamespaceTerminalReceipt(t, "provider", "generation")
	aggregate := mustProviderRunTerminalReceipt(t, namespace)
	terminal, err := newQualifiedRunTerminalReceipt([]qualifiedProviderEvidence{{identity: Identity{
		Family: FamilyKimi, Instance: "provider", ProfileGeneration: "profile", AdapterProfile: "adapter", Version: "1.0.0",
		Executable: "/private/bin/provider", ExecutableSHA256: "sha256", Launcher: "/private/bin/provider", LauncherSHA256: "sha256",
		SnapshotManifest: "manifest", NamespaceLease: "lease", NamespaceGeneration: "generation",
	}, qualificationReceiptIDs: []string{"qualification"}, packetTransportReceiptIDs: []string{"transport"}}}, aggregate)
	if err != nil {
		t.Fatal(err)
	}
	return terminal
}

func assertServiceCalls(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("call count = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("call order = %v, want %v", got, want)
		}
	}
}

// stagingObservedProviderFake is a qualified provider registry that also owns
// per-invocation output staging, exactly as the production CLI registry does.
type stagingObservedProviderFake struct {
	observedProviderFake
}

func (fake *stagingObservedProviderFake) ProviderOutputStagingDestination(
	providerInstance string,
	attemptID domain.AttemptID,
	purpose ports.ProviderInvocationPurpose,
) (ports.StagedOutputDestination, ports.ProviderOutputTransport, bool) {
	if providerInstance != "zcode-logic" {
		return ports.StagedOutputDestination{}, ports.ProviderOutputTransportStdout, true
	}
	ordinal := 0
	if purpose == ports.ProviderInvocationRepair {
		ordinal = 1
	}
	destination, err := ports.NewStagedOutputDestination(
		fmt.Sprintf("/scratch/output/%s-%d", attemptID.String(), ordinal), "role-report.md",
	)
	if err != nil {
		return ports.StagedOutputDestination{}, ports.ProviderOutputTransportStdout, false
	}
	return destination, ports.ProviderOutputTransportStagedFile, true
}

func TestProviderOutputStagingLocatorRequiresRegistryAuthority(t *testing.T) {
	if locator := providerOutputStagingLocator(nil); locator != nil {
		t.Fatalf("absent provider produced locator %#v", locator)
	}
	if locator := providerOutputStagingLocator(&observedProviderFake{}); locator != nil {
		t.Fatalf("stdout-only provider produced locator %#v", locator)
	}
	var typedNil *stagingObservedProviderFake
	if locator := providerOutputStagingLocator(typedNil); locator != nil {
		t.Fatalf("typed-nil registry produced locator %#v", locator)
	}
	if locator := providerOutputStagingLocator(&stagingObservedProviderFake{}); locator == nil {
		t.Fatal("staging registry authority was not detected")
	}
}

func TestPromptSourceStatesEachStagedLaunchDestination(t *testing.T) {
	templates, err := LoadDefaultTemplateSet(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	base, err := templates.ComposeRootReview(domain.RoleLogic, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantBase := []string{
		"builtin:review/common",
		"builtin:run/review",
		"builtin:roles/logic",
		"builtin:output/provider-review-wire",
	}
	input, err := NewImmutableReviewInput(reviewRunPatchTarget(t), nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	locator := providerOutputStagingLocator(&stagingObservedProviderFake{})
	staged, err := newPromptSource(input, templates, &reviewRunPromptIssuer{}, reviewRunRoleTask, locator)
	if err != nil {
		t.Fatal(err)
	}
	initialJob := reviewRunStagedJob(t, "zcode-logic", domain.InvocationInitial, 1)
	repairJob := reviewRunStagedJob(t, "zcode-logic", domain.InvocationRepair, 2)

	initialTemplate, err := staged.composeOutputDestination(base, initialJob)
	if err != nil {
		t.Fatal(err)
	}
	assertLayerIDs(t, initialTemplate, append(append([]string(nil), wantBase...), review.OutputDestinationTrustedLayerID))
	repairBase, err := templates.ComposeRootReviewRepair(base, validation.RepairPlan{})
	if err != nil {
		t.Fatal(err)
	}
	repairTemplate, err := staged.composeOutputDestination(repairBase, repairJob)
	if err != nil {
		t.Fatal(err)
	}
	assertLayerIDs(t, repairTemplate, append(append([]string(nil), wantBase...),
		"builtin:repair/provider-review", "review:repair-plan", review.OutputDestinationTrustedLayerID))

	initialDestination, initialStaged := review.ResolveStagedOutputDestination(locator, initialJob)
	repairDestination, repairStaged := review.ResolveStagedOutputDestination(locator, repairJob)
	if !initialStaged || !repairStaged || initialDestination == repairDestination {
		t.Fatalf("launch destinations = %#v / %#v", initialDestination, repairDestination)
	}
	for _, test := range []struct {
		name     string
		template prompt.TrustedTemplate
		want     ports.StagedOutputDestination
		other    ports.StagedOutputDestination
	}{
		{name: "initial", template: initialTemplate, want: initialDestination, other: repairDestination},
		{name: "repair", template: repairTemplate, want: repairDestination, other: initialDestination},
	} {
		t.Run(test.name, func(t *testing.T) {
			layer, layerErr := review.OutputDestinationTrustedLayer(test.want)
			if layerErr != nil {
				t.Fatal(layerErr)
			}
			if !bytes.HasSuffix(test.template.Bytes(), layer.Bytes()) {
				t.Fatal("output destination layer is not the last trusted layer")
			}
			if !bytes.Contains(test.template.Bytes(), []byte(test.want.AbsolutePath())) ||
				bytes.Contains(test.template.Bytes(), []byte(test.other.AbsolutePath())) {
				t.Fatalf("launch template does not state exactly %q", test.want.AbsolutePath())
			}
		})
	}

	// A provider instance the registry keeps on stdout, and a provider without
	// staging authority at all, both leave the template untouched.
	stdoutJob := reviewRunStagedJob(t, "agy-logic", domain.InvocationInitial, 1)
	untouched, err := staged.composeOutputDestination(base, stdoutJob)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := newPromptSource(input, templates, &reviewRunPromptIssuer{}, reviewRunRoleTask, providerOutputStagingLocator(&observedProviderFake{}))
	if err != nil {
		t.Fatal(err)
	}
	absent, err := plain.composeOutputDestination(base, initialJob)
	if err != nil {
		t.Fatal(err)
	}
	if untouched.SHA256() != base.SHA256() || absent.SHA256() != base.SHA256() {
		t.Fatal("stdout transport launches changed the trusted template")
	}
}

func reviewRunStagedJob(t *testing.T, instance string, purpose domain.InvocationPurpose, ordinal uint64) review.InvocationJob {
	t.Helper()
	key, err := ports.ParseConcurrencyKey(instance)
	if err != nil {
		t.Fatal(err)
	}
	route, err := ports.NewProviderRoute(instance, key)
	if err != nil {
		t.Fatal(err)
	}
	target, err := domain.NewTargetIdentity(domain.TargetIdentityInput{
		Kind: domain.TargetStdin, SHA256: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	limits, err := review.NewInvocationLimits(time.Second, 1024, 1024)
	if err != nil {
		t.Fatal(err)
	}
	attemptID, err := domain.ParseAttemptID("a_019f5a09-5eec-7001-8001-000000000003")
	if err != nil {
		t.Fatal(err)
	}
	job, err := review.NewInvocationJob(
		domain.RoleLogic, route, target, limits, attemptID, purpose, ordinal,
	)
	if err != nil {
		t.Fatal(err)
	}
	return job
}
