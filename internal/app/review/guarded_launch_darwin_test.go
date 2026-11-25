//go:build darwin && arm64

package review

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	processadapter "github.com/irootkernel/mulgae/internal/adapters/process"
	"github.com/irootkernel/mulgae/internal/adapters/providercli"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// TestMain routes the binary's hidden launch modes exactly like the real
// entrypoint. It is the production ExecInheritedDirectory trampoline, not a
// simulated failure.
func TestMain(m *testing.M) {
	handled, err := processadapter.ExecInheritedDirectory(os.Args)
	if handled {
		if err != nil {
			_, _ = os.Stderr.WriteString("mulgae: provider launch boundary failed\n")
			os.Exit(10)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type guardedLaunchClock struct{}

func (guardedLaunchClock) Now() time.Time { return time.Now().UTC() }

type guardedLaunchRecordingRunner struct {
	t        *testing.T
	process  ports.ProcessRunner
	control  ports.AnchoredRoot
	identity ports.TerminalRuntimeIdentity
	observed ports.ProcessObservation
	calls    int
	guarded  bool
}

func (runner *guardedLaunchRecordingRunner) RunTerminal(ctx context.Context, request ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
	runner.calls++
	process := request.Process()
	if dir, _, ok := process.LaunchDirectory(); ok {
		defer dir.Close()
	}
	boundary, ok := process.LiveReadOnlyBoundary()
	runner.guarded = ok && boundary.PaneTTY()
	launch, err := ports.NewPaneLaunchRequest(process, runner.control)
	if err != nil {
		runner.t.Fatal(err)
	}
	spec, err := processadapter.NewPaneLaunchBuilder().BuildPaneLaunch(ctx, launch)
	if err != nil {
		runner.t.Fatal(err)
	}
	argv := spec.Argv()
	argv[2] = "invalid-control-file"
	child, err := ports.NewProcessRequest(spec.Executable(), argv, nil, process.WorkingDirectory(), nil, process.Timeout())
	if err != nil {
		runner.t.Fatal(err)
	}
	observation, err := runner.process.Run(ctx, child)
	if err != nil {
		runner.t.Fatal(err)
	}
	exit, exited := observation.ExitCode()
	if !exited || observation.Termination() != ports.ProcessTerminationExited {
		runner.t.Fatalf("expected natural trampoline exit: %v", observation.Termination())
	}
	final, err := ports.NewExitedProcessFinalTermination(exit)
	if err != nil {
		runner.t.Fatal(err)
	}
	// Runner.Run verifies process-group absence before returning a normal exit.
	lifecycle, err := ports.NewProcessLifecycleReceipt(final, true, nil)
	if err != nil {
		runner.t.Fatal(err)
	}
	runner.observed, err = ports.NewStartedProcessObservation(observation.Stdout(), observation.Stderr(),
		observation.Termination(), observation.StdinWriteReceipt(), lifecycle, observation.StartedAt(), observation.EndedAt())
	if err != nil {
		runner.t.Fatal(err)
	}
	return ports.NewTerminalExecutionObservation(ports.TerminalExecutionObservationInput{
		Process: runner.observed, RuntimeIdentity: runner.identity, ExitedBeforeReport: true,
	})
}

func (runner *guardedLaunchRecordingRunner) RuntimeIdentity(context.Context) (ports.TerminalRuntimeIdentity, error) {
	return runner.identity, nil
}

func (*guardedLaunchRecordingRunner) DrainLabeledPanes(context.Context, string, string) error {
	return nil
}
func (*guardedLaunchRecordingRunner) Close(context.Context) error { return nil }
func (*guardedLaunchRecordingRunner) VerifyProviderSpawn(ctx context.Context, _ providercli.RuntimeDefinition) error {
	return ctx.Err()
}

// TestGuardedLaunchAbortTraversesRealFailureClassification proves that an
// actual pane-trampoline abort crosses the registry's terminal driver and
// normal application policy. The typed pre-readiness failure closes the
// attempt without repair, extraction, or output authority.
func TestGuardedLaunchAbortTraversesRealFailureClassification(t *testing.T) {
	const binary = "/usr/bin/true"
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source, neutral := filepath.Join(base, "source"), filepath.Join(base, "neutral")
	credentials, namespace := filepath.Join(base, "credentials"), filepath.Join(base, "invocation")
	control := filepath.Join(base, "control")
	for _, path := range []string{source, neutral, credentials, namespace, control} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(source, "source.go"), []byte("package fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	root := func(path string) ports.AnchoredRoot {
		value, err := ports.NewAnchoredRoot(path)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}

	// Real live-source execution admission over the real directories.
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	path, _ := ports.NewSafeRelativePath("source.go")
	target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
	reader := &runtimeLiveReader{
		coordinatorLiveReader: coordinatorLiveReader{target},
		binding:               ports.ProjectBindingObservation{Root: root(source), RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}},
	}
	home, err := providercli.OpenReviewerHome(root(neutral), []byte("Read only the admitted fixture.\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer home.Close()
	execution, err := ports.NewLiveReviewExecution(context.Background(), reader, home, []ports.AnchoredRoot{root(credentials)})
	if err != nil {
		t.Fatal(err)
	}
	execution, err = ports.NewLiveReviewExecutionWithControlPlane(execution, []ports.AnchoredRoot{root(control)}, nil)
	if err != nil {
		t.Fatal(err)
	}

	processRunner, err := processadapter.NewRunner(guardedLaunchClock{})
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	runtimeIdentity, err := ports.NewTerminalRuntimeIdentity("/synthetic/hc", digest, "0.1.0", 1)
	if err != nil {
		t.Fatal(err)
	}
	runner := &guardedLaunchRecordingRunner{t: t, process: processRunner, control: root(control), identity: runtimeIdentity}
	policy, err := providercli.RuntimeSafetyPolicyForFamily(providercli.CredentialSourceGrok)
	if err != nil {
		t.Fatal(err)
	}
	const instance = "grok-guarded-abort"
	transport, err := providercli.NewRuntimeTransport(ports.ProviderPacketChannelTerminal, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	definition, err := providercli.NewProductionRuntimeDefinitionWithTransportAndSafetyPolicy(
		providercli.FamilyGrok, instance, "1.0.89", binary, digest, binary, digest, "", "",
		"guarded-abort-profile", "guarded-abort-generation", policy.Identity(), []string{binary},
		transport, nil, neutral, 30*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	namespaces, err := providercli.NewNamespaceFactory(namespace)
	if err != nil {
		t.Fatal(err)
	}
	factory, err := providercli.NewCredentialProjectingNamespaceFactoryWithPolicies(namespaces, base,
		map[string]providercli.CredentialSourceFamily{instance: providercli.CredentialSourceGrok},
		map[string]providercli.RuntimeSafetyPolicy{instance: policy})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := providercli.NewProductionRegistryWithTerminalRunner(t.Context(), processRunner, runner, factory, runner, definition)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := registry.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()

	// Normal application runtime around the real provider, with the fixture
	// material rebound to the live source identity exactly like the live
	// source runtime test.
	identity, err := evidence.NewLiveSourceIdentity(target)
	if err != nil {
		t.Fatal(err)
	}
	_, job, material := providerRuntimeExplicitFixture(t, nil)
	job.route = coordinatorTypesRoute(t, instance)
	job.target, err = identity.RunTarget()
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := prompt.NewCompiler(material.Prompt.TrustedTemplate(), explicitRuntimeTestIssuer{source: material.Prompt.Scope().SourceInvocationID(), execution: material.Prompt.Scope().ExecutionInvocationID()})
	if err != nil {
		t.Fatal(err)
	}
	material.Target = identity.Bytes()
	material.Prompt, err = compiler.Compile(prompt.CompileInput{Scope: material.Prompt.Scope().FrameScope().Coordinates(), ReviewTarget: prompt.NewPayload(material.Target)})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewObservedProviderInvocationRuntimeInLiveSource(
		registry, explicitRuntimePromptSource{material}, execution,
		newReviewValidator(t), providerRuntimeDiagnosticResolver{runID: job.RunID(), sink: &providerRuntimeRawSink{}},
	)
	if err != nil {
		t.Fatal(err)
	}

	outcome := runtime.Invoke(context.Background(), job)
	exit, exited := runner.observed.ExitCode()
	if runner.calls != 1 || !runner.guarded || !exited || exit != 10 || !runner.observed.ProcessGroupAbsent() || len(runner.observed.SignalRequests()) != 0 || !strings.Contains(string(runner.observed.Stderr()), "provider launch boundary failed") {
		t.Fatalf("guarded trampoline abort was not executed: calls=%d guarded=%t exited=%t code=%d stderr=%q", runner.calls, runner.guarded, exited, exit, runner.observed.Stderr())
	}
	if outcome.Succeeded() {
		t.Fatal("aborted guarded launch produced a successful outcome")
	}
	if _, ok := outcome.Output(); ok {
		t.Fatal("aborted guarded launch produced output authority")
	}
	if outcome.RuntimeArtifactsExpected() {
		t.Fatal("aborted guarded launch expects publication artifacts")
	}
	condition, ok := outcome.Condition()
	if !ok {
		t.Fatalf("aborted guarded launch lost its typed condition: %#v", outcome)
	}
	if condition != AttemptConditionProviderSpawnFailed {
		t.Fatalf("aborted guarded launch condition = %q, want provider_spawn_failed", condition)
	}
	row, found := lookupTransitionPolicy(condition)
	if !found {
		t.Fatalf("condition %q has no transition policy", condition)
	}
	if row.action != transitionActionFailClosed {
		t.Fatalf("condition %q action = %d, want fail-closed", condition, row.action)
	}
	if !row.providerUnusable {
		t.Fatalf("condition %q did not mark the provider unusable", condition)
	}
	runtime.mu.Lock()
	pendingRepair, pendingExtraction := len(runtime.pending), len(runtime.pendingExtraction)
	runtime.mu.Unlock()
	if pendingRepair != 0 || pendingExtraction != 0 {
		t.Fatalf("aborted guarded launch scheduled repair (%d) or extraction (%d)", pendingRepair, pendingExtraction)
	}
}
