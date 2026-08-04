//go:build darwin && arm64 && !liveprovider

package providercli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	processadapter "github.com/irootkernel/mulgae/internal/adapters/process"
	runtimeadapter "github.com/irootkernel/mulgae/internal/adapters/runtime"
	workspaceadapter "github.com/irootkernel/mulgae/internal/adapters/workspace"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// The offline fixture re-executes the race-instrumented test binary through the
// production native-home trampoline. Package and workspace test jobs can put
// that child under severe startup pressure before TestMain reaches the shell
// fixture, so successful fixture paths need test-only scheduling headroom. The
// explicit timeout case below retains its 250ms behavioral deadline.
const agyLifecycleFixtureTimeout = 5 * time.Minute

func TestMain(m *testing.M) {
	handled, err := processadapter.ExecInheritedDirectory(os.Args)
	if handled {
		if err != nil {
			os.Exit(125)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// TestAgyLifecycleOfflineRealProcess exercises the production registry path with
// a shell fixture, not an installed AGY binary. The fixture asserts its exact
// process contract before emitting a deterministic response.
func TestAgyLifecycleOfflineRealProcess(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("native-home descriptor binding is Darwin-only")
	}

	t.Run("strict print output is bounded and drains the complete process group", func(t *testing.T) {
		h := newAgyLifecycleHarness(t, "post", 256, agyLifecycleFixtureTimeout)
		defer h.close(t)
		observation, err := h.registry.Observe(context.Background(), h.invocation(t))
		if err != nil {
			t.Fatal(err)
		}
		if !observation.Succeeded() {
			t.Fatalf("AGY observation did not succeed: %#v", observation)
		}
		if !observation.ProcessGroupAbsent() {
			t.Fatalf("AGY post-output observation retained a process group: %#v", observation)
		}
		if got := string(observation.ProcessObservation().Stdout()); got != `{"findings":[]}` {
			t.Fatalf("strict AGY print output = %q", got)
		}
		child := waitAgyChildPID(t, h.childPID)
		if err := syscall.Kill(child, 0); !errors.Is(err, syscall.ESRCH) {
			t.Fatalf("AGY post-output child %d survived process-group termination: %v", child, err)
		}
	})
	t.Run("TERM-handler trailing bytes fail as artifacts after full drain", func(t *testing.T) {
		h := newAgyLifecycleHarness(t, "trailing", 256, agyLifecycleFixtureTimeout)
		defer h.close(t)
		observation, err := h.registry.Observe(context.Background(), h.invocation(t))
		if err != nil {
			t.Fatal(err)
		}
		if observation.Status() != ports.ProviderExecutionStatusArtifactFailure ||
			observation.DiagnosticCode() != "post_output_trailing_bytes" {
			t.Fatalf("status = %q, diagnostic = %q", observation.Status(), observation.DiagnosticCode())
		}
		if got := string(observation.ProcessObservation().Stdout()); got != `{"findings":[]}x` {
			t.Fatalf("stdout = %q, want complete trailing evidence", got)
		}
		if !observation.ProcessGroupAbsent() {
			t.Fatalf("trailing-byte process group was not drained: %#v", observation)
		}
	})

	t.Run("SIGTERM-resistant process escalates and still succeeds", func(t *testing.T) {
		h := newAgyLifecycleHarness(t, "resistant", 256, agyLifecycleFixtureTimeout)
		defer h.close(t)
		observation, err := h.registry.Observe(context.Background(), h.invocation(t))
		if err != nil {
			t.Fatal(err)
		}
		if !observation.Succeeded() || !observation.ProcessGroupAbsent() {
			t.Fatalf("SIGTERM-resistant AGY did not complete after escalation: %#v", observation)
		}
		escalated := false
		for _, request := range observation.ProcessObservation().SignalRequests() {
			if request.Reason() == ports.ProcessGroupSignalRequestPostOutputEscalation {
				escalated = true
			}
		}
		if !escalated {
			t.Fatal("SIGTERM-resistant AGY did not record escalation")
		}
	})

	t.Run("SIGTERM handler exit after stable output still succeeds", func(t *testing.T) {
		h := newAgyLifecycleHarness(t, "handled", 256, agyLifecycleFixtureTimeout)
		defer h.close(t)
		observation, err := h.registry.Observe(context.Background(), h.invocation(t))
		if err != nil {
			t.Fatal(err)
		}
		if !observation.Succeeded() || !observation.ProcessGroupAbsent() {
			t.Fatalf("handled post-output SIGTERM did not preserve the accepted AGY result: %#v", observation)
		}
		if got := string(observation.ProcessObservation().Stdout()); got != `{"findings":[]}` {
			t.Fatalf("handled post-output AGY stdout = %q", got)
		}
		if got := string(observation.ProcessObservation().Stderr()); !strings.Contains(got, "Error: timeout waiting for response\n") {
			t.Fatalf("handled post-output AGY stderr omitted native signal-handler text: %q", got)
		}
	})

	for _, test := range []struct {
		name        string
		mode        string
		cap         int64
		timeout     time.Duration
		termination ports.ProcessTermination
		status      ports.ProviderExecutionStatus
	}{
		{name: "timeout", mode: "timeout", cap: 256, timeout: 250 * time.Millisecond, termination: ports.ProcessTerminationTimedOut},
		{name: "cancellation", mode: "timeout", cap: 256, timeout: agyLifecycleFixtureTimeout, termination: ports.ProcessTerminationCancelled},
		{name: "output cap", mode: "oversize", cap: 64, timeout: agyLifecycleFixtureTimeout, termination: ports.ProcessTerminationStdoutLimit},
		{name: "malformed strict output", mode: "malformed", cap: 256, timeout: agyLifecycleFixtureTimeout, status: ports.ProviderExecutionStatusArtifactFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newAgyLifecycleHarness(t, test.mode, test.cap, test.timeout)
			defer h.close(t)
			ctx := context.Background()
			if test.name == "cancellation" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				time.AfterFunc(25*time.Millisecond, cancel)
			}
			observation, err := h.registry.Observe(ctx, h.invocation(t))
			if err != nil {
				t.Fatalf("AGY %s returned runner error: %v", test.name, err)
			}
			if test.status != "" && observation.Status() != test.status {
				t.Fatalf("AGY %s status = %q, want %q", test.name, observation.Status(), test.status)
			}
			if test.termination != "" && observation.Termination() != test.termination {
				t.Fatalf("AGY %s termination = %q, want %q", test.name, observation.Termination(), test.termination)
			}
		})
	}

	t.Run("spawn permission drift fails closed", func(t *testing.T) {
		h := newAgyLifecycleHarness(t, "valid", 256, agyLifecycleFixtureTimeout)
		defer h.close(t)
		if err := os.Chmod(h.executable, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := h.registry.Observe(context.Background(), h.invocation(t)); err == nil {
			t.Fatal("AGY executable permission drift reached spawn")
		}
	})

	t.Run("snapshot drift fails before spawn", func(t *testing.T) {
		h := newAgyLifecycleHarness(t, "valid", 256, agyLifecycleFixtureTimeout)
		defer h.close(t)
		target := filepath.Join(h.workspace.WorkspaceSnapshotIdentity().SnapshotPath(), "roadmap.md")
		if err := os.Chmod(target, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte("drift"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := h.registry.Observe(context.Background(), h.invocation(t)); err == nil {
			t.Fatal("AGY snapshot drift reached spawn")
		}
		if err := os.WriteFile(target, []byte("offline roadmap"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(target, 0444); err != nil {
			t.Fatal(err)
		}
	})
}

type agyLifecycleHarness struct {
	registry   *Registry
	workspace  ports.QualificationWorkspaceLease
	executable string
	childPID   string
}

func newAgyLifecycleHarness(t *testing.T, mode string, stdoutCap int64, timeout time.Duration) agyLifecycleHarness {
	t.Helper()
	root := agyLifecycleCanonicalTempDir(t)
	nativeHome := filepath.Join(root, "native-home")
	if err := os.Mkdir(nativeHome, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "bootstrap"), 0700); err != nil {
		t.Fatal(err)
	}
	childPID := filepath.Join(root, "child.pid")
	executable := filepath.Join(root, "agy-offline")
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then printf '1.1.2\n'; exit 0; fi
[ "$HOME" = "$MULGAE_AGY_EXPECTED_HOME" ] || exit 91
[ ! -e "$HOME/.mulgae-credential-copy" ] || exit 92
[ "$PWD" = "$MULGAE_AGY_EXPECTED_CWD" ] || exit 93
[ "$1" = "--new-project" ] && [ "$2" = "--sandbox" ] && [ "$3" = "--dangerously-skip-permissions" ] && [ "$4" = "--add-dir" ] && [ "$5" = "$MULGAE_AGY_EXPECTED_CWD" ] && [ "$6" = "--mode" ] && [ "$7" = "plan" ] && [ "$8" = "--effort" ] && [ "$9" = "low" ] && [ "${10}" = "--print-timeout" ] && [ "${11}" = "$MULGAE_AGY_EXPECTED_PRINT_TIMEOUT" ] && [ "${12}" = "--print" ] || exit 94
case "$MULGAE_AGY_TEST_MODE" in
post) printf '{"findings":[]}'; (sleep 30) & echo $! > "$MULGAE_AGY_CHILD_PID"; wait ;;
trailing) trap 'printf x; exit 0' TERM; printf '{"findings":[]}'; while :; do sleep 1; done ;;
resistant) trap '' TERM; printf '{"findings":[]}'; while :; do sleep 1; done ;;
handled) trap 'printf "Error: timeout waiting for response\n" >&2; exit 1' TERM; printf '{"findings":[]}'; while :; do sleep 1; done ;;
timeout) sleep 30 ;;
oversize) i=0; while [ $i -lt 2048 ]; do printf x; i=$((i+1)); done ;;
malformed) printf '{\n' ;;
valid) printf '{"findings":[]}' ;;
esac
`
	if err := os.WriteFile(executable, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(script))
	hash := "sha256:" + hex.EncodeToString(sum[:])
	workspace := agyLifecycleWorkspace(t, filepath.Join(root, "snapshots"))
	policy, err := RuntimeSafetyPolicyForFamilyAndWorkspaceRoot(CredentialSourceAGY, workspace.WorkspaceSnapshotIdentity().SnapshotPath())
	if err != nil {
		t.Fatal(err)
	}
	base, err := NewNamespaceFactory(filepath.Join(root, "namespaces"))
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewCredentialProjectingNamespaceFactoryWithPoliciesAndNativeHomes(base, filepath.Join(root, "bootstrap"), map[string]CredentialSourceFamily{"agy-offline": CredentialSourceAGY}, map[string]RuntimeSafetyPolicy{"agy-offline": policy}, map[string]string{"agy-offline": nativeHome})
	if err != nil {
		t.Fatal(err)
	}
	key, err := ports.ParseConcurrencyKey("agy_offline_lane")
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewRuntimeTransport(ports.ProviderPacketChannelArgvLiteral, 13, "")
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := ports.NewBoundedPostOutputLifecycle(ports.ProcessOutputFramingTerminalJSONObject, 20*time.Millisecond, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	env := []ports.EnvironmentVariable{
		agyLifecycleEnv(t, "MULGAE_AGY_TEST_MODE", mode), agyLifecycleEnv(t, "MULGAE_AGY_EXPECTED_HOME", nativeHome),
		agyLifecycleEnv(t, "MULGAE_AGY_EXPECTED_CWD", workspace.WorkspaceSnapshotIdentity().SnapshotPath()), agyLifecycleEnv(t, "MULGAE_AGY_CHILD_PID", childPID),
		agyLifecycleEnv(t, "MULGAE_AGY_EXPECTED_PRINT_TIMEOUT", agyPrintTimeout(timeout).String()),
	}
	definition, err := NewProductionRuntimeDefinitionWithTransportAndSafetyPolicyAndPostOutputLifecycle(FamilyAgy, "agy-offline", "1.1.4", executable, hash, executable, hash, key, "agy-offline", "offline-v1", policy.Identity(), []string{executable}, transport, lifecycle, env, workspace.WorkspaceSnapshotIdentity().SnapshotPath(), timeout, stdoutCap, 256)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := processadapter.NewRunner(runtimeadapter.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewProductionRegistry(runner, factory, agyLifecycleSpawnVerifier{}, definition)
	if err != nil {
		t.Fatal(err)
	}
	return agyLifecycleHarness{registry: registry, workspace: workspace, executable: executable, childPID: childPID}
}

func (h agyLifecycleHarness) invocation(t *testing.T) ports.ProviderInvocation {
	t.Helper()
	packet, err := ports.NewProviderPacket([]byte("offline packet"), agyLifecyclePacketDigest([]byte("offline packet")))
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := domain.ParseAttemptID("a_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := ports.NewProviderInvocationWithPacketInWorkspace(domain.RoleLogic, "agy-offline", attempt, ports.ProviderInvocationInitial, packet, "i_019f596a-cf80-7c67-b265-f37053d51ccf", "019f596a-d174-7321-b920-c2d312c82cc2", h.workspace)
	if err != nil {
		t.Fatal(err)
	}
	return invocation
}

func (h agyLifecycleHarness) close(t *testing.T) {
	t.Helper()
	namespace := h.registry.namespaces["agy-offline"]
	namespaceReceipt, err := namespace.DrainTerminal(context.Background())
	if err != nil || !namespaceReceipt.Valid() {
		t.Fatalf("terminal namespace drain: receipt=%#v err=%v", namespaceReceipt, err)
	}
	receipt, err := h.registry.Close(context.Background())
	if err != nil || !receipt.Valid() {
		t.Fatalf("terminal registry drain: receipt=%#v err=%v", receipt, err)
	}
	workspaceReceipt, err := h.workspace.DrainTerminal(context.Background())
	if err != nil || !workspaceReceipt.Valid() {
		t.Fatalf("terminal snapshot drain: receipt=%#v err=%v", workspaceReceipt, err)
	}
}

type agyLifecycleSpawnVerifier struct{}

func (agyLifecycleSpawnVerifier) VerifyProviderSpawn(_ context.Context, definition RuntimeDefinition) error {
	info, err := os.Lstat(definition.Executable())
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return errors.New("offline AGY executable identity drift")
	}
	bytes, err := os.ReadFile(definition.Executable())
	if err != nil {
		return errors.New("offline AGY executable identity drift")
	}
	sum := sha256.Sum256(bytes)
	if "sha256:"+hex.EncodeToString(sum[:]) != definition.ExecutableSHA256() ||
		definition.Launcher() != definition.Executable() ||
		definition.LauncherSHA256() != definition.ExecutableSHA256() {
		return errors.New("offline AGY executable identity drift")
	}
	return nil
}

type agyLifecycleDetector struct{}

func (agyLifecycleDetector) DetectWorkspaceContent(context.Context, ports.SafeRelativePath, []byte) (ports.WorkspaceContentVerdict, error) {
	return ports.WorkspaceContentClean, nil
}

func agyLifecycleWorkspace(t *testing.T, root string) ports.QualificationWorkspaceLease {
	t.Helper()
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	anchored, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	materializer, err := workspaceadapter.NewMaterializer(anchored, agyLifecycleDetector{})
	if err != nil {
		t.Fatal(err)
	}
	path, err := ports.NewSafeRelativePath("roadmap.md")
	if err != nil {
		t.Fatal(err)
	}
	bytes := []byte("offline roadmap")
	sum := sha256.Sum256(bytes)
	file, err := ports.NewWorkspaceSnapshotFile(path, bytes, "sha256:"+hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewWorkspaceSnapshotRequest([]ports.WorkspaceSnapshotFile{file}, "agy-offline-v1")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := materializer.MaterializeQualificationLease(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

func agyLifecycleEnv(t *testing.T, name, value string) ports.EnvironmentVariable {
	t.Helper()
	variable, err := ports.NewEnvironmentVariable(name, value)
	if err != nil {
		t.Fatal(err)
	}
	return variable
}
func agyLifecyclePacketDigest(value []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("Mulgae-PROVIDER-STDIN/1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(value)
	return hex.EncodeToString(hash.Sum(nil))
}
func agyLifecycleCanonicalTempDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func waitAgyChildPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		bytes, err := os.ReadFile(path)
		if err == nil {
			pid, parseErr := strconv.Atoi(strings.TrimSpace(string(bytes)))
			if parseErr == nil && pid > 0 {
				return pid
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("AGY fixture did not record child PID at %q", path)
	return 0
}
