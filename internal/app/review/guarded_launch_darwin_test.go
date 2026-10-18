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

// guardedLaunchFaultEnvironment is a test-only fault injector: when the launch
// child (this same test binary, re-entered through a hidden descriptor-bound
// launch mode) sees it, TestMain corrupts the private launch arguments before
// the trusted trampoline validates them, forcing the real boundary-abort
// failure surface before sandbox or provider execution ever starts.
const guardedLaunchFaultEnvironment = "MULGAE_TEST_GUARDED_LAUNCH_FAULT"

// TestMain routes the binary's hidden launch modes exactly like the real
// entrypoint. It is the production ExecInheritedDirectory trampoline, not a
// simulated failure.
func TestMain(m *testing.M) {
	if os.Getenv(guardedLaunchFaultEnvironment) != "" && len(os.Args) >= 3 && strings.HasPrefix(os.Args[1], "__mulgae_") {
		os.Args[2] = "faulted"
	}
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
	ports.ProcessRunner
	conversation ports.ProviderConversationRunner
	boundary     ports.LiveReadOnlyBoundary
	observed     ports.ProcessObservation
	calls        int
	guarded      bool
}

func (runner *guardedLaunchRecordingRunner) Converse(ctx context.Context, request ports.ProcessRequest, driver ports.ProviderSessionDriver) (ports.ProcessObservation, error) {
	runner.calls++
	// Codex normally uses its native guard. Add the real outer guard here to
	// exercise the shared guarded trampoline failure without provider setup.
	request, err := ports.NewLiveReadOnlyProcessRequest(request, runner.boundary)
	if err != nil {
		return ports.ProcessObservation{}, err
	}
	_, runner.guarded = request.LiveReadOnlyBoundary()
	observation, err := runner.conversation.Converse(ctx, request, driver)
	runner.observed = observation
	return observation, err
}

// TestGuardedLaunchAbortTraversesRealFailureClassification proves that an
// actual trampoline-aborted guarded launch crosses the real registry protocol
// driver, real process runner, and normal application policy: the attempt
// fails closed with a typed provider condition that permits only the bounded
// same-provider retry, never repair, extraction, or any output authority.
func TestGuardedLaunchAbortTraversesRealFailureClassification(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source, neutral := filepath.Join(base, "source"), filepath.Join(base, "neutral")
	credentials, namespace := filepath.Join(base, "credentials"), filepath.Join(base, "invocation")
	for _, path := range []string{source, neutral, credentials, namespace} {
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

	// Real runner and real registry with the real protocol driver; the fault
	// environment is inherited by the launch child, whose TestMain aborts the
	// trusted launch before any sandbox or provider execution.
	processRunner, err := processadapter.NewRunner(guardedLaunchClock{})
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := ports.NewLiveReadOnlyBoundary([]ports.AnchoredRoot{root(source), home.Root()}, []ports.AnchoredRoot{root(credentials)}, root(namespace))
	if err != nil {
		t.Fatal(err)
	}
	runner := &guardedLaunchRecordingRunner{ProcessRunner: processRunner, conversation: processRunner, boundary: boundary}
	environment := []ports.EnvironmentVariable{
		mustGuardedEnvironment(t, "PATH", "/usr/bin:/bin"),
		mustGuardedEnvironment(t, guardedLaunchFaultEnvironment, "1"),
	}
	definition, err := providercli.NewRuntimeDefinition(
		providercli.FamilyCodex, "codex-guarded-abort", "1.0.0", binary, "",
		"guarded-abort-profile", []string{binary}, environment, neutral, time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := providercli.NewRegistry(runner, definition)
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
	job.route = coordinatorTypesRoute(t, "codex-guarded-abort")
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
	// The real protocol driver maps the pre-provider stream end to a typed
	// provider failure cause; application policy must classify it as an
	// ordinary bounded-retry provider condition, never a repairable output
	// condition and never an invented launch classification.
	if condition != AttemptConditionProviderTurnFailed && condition != AttemptConditionProviderUnavailable {
		t.Fatalf("aborted guarded launch condition = %q, want a typed provider failure", condition)
	}
	row, found := lookupTransitionPolicy(condition)
	if !found {
		t.Fatalf("condition %q has no transition policy", condition)
	}
	if row.action != transitionActionRetryOnly {
		t.Fatalf("condition %q action = %d, want retry-only", condition, row.action)
	}
	if row.providerUnusable {
		t.Fatalf("condition %q marked the provider unusable", condition)
	}
	runtime.mu.Lock()
	pendingRepair, pendingExtraction := len(runtime.pending), len(runtime.pendingExtraction)
	runtime.mu.Unlock()
	if pendingRepair != 0 || pendingExtraction != 0 {
		t.Fatalf("aborted guarded launch scheduled repair (%d) or extraction (%d)", pendingRepair, pendingExtraction)
	}
}

func mustGuardedEnvironment(t *testing.T, name, value string) ports.EnvironmentVariable {
	t.Helper()
	variable, err := ports.NewEnvironmentVariable(name, value)
	if err != nil {
		t.Fatal(err)
	}
	return variable
}
