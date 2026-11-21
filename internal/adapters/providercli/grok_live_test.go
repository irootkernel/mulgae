//go:build liveprovider && darwin && arm64

package providercli

import (
	"context"
	"crypto/sha256"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	herdradapter "github.com/irootkernel/mulgae/internal/adapters/herdr"
	processadapter "github.com/irootkernel/mulgae/internal/adapters/process"
	runtimeadapter "github.com/irootkernel/mulgae/internal/adapters/runtime"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestLiveGrokTerminalSmoke(t *testing.T) {
	executable, err := filepath.EvalSymlinks(filepath.Join(mustLiveGrokHome(t), ".grok", "bin", "grok"))
	if err != nil {
		t.Fatal(err)
	}
	nativeHome, err := ports.NewAnchoredRoot(mustLiveGrokHome(t))
	if err != nil {
		t.Fatal(err)
	}
	launchDir, neutralCWD, err := openNeutralQualificationDirectory(nativeHome.String())
	if err != nil {
		t.Fatal(err)
	}
	lease := mustLiveGrokNamespace(t)
	defer drainLiveGrokNamespace(t, lease)

	session, err := herdradapter.NewSession(herdradapter.SessionOptions{
		Clock:         runtimeadapter.SystemClock{},
		LaunchBuilder: processadapter.NewPaneLaunchBuilder(),
		NativeHome:    nativeHome,
	})
	if err != nil {
		_ = launchDir.Close()
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if closeErr := session.Close(cleanupCtx); closeErr != nil {
			t.Errorf("close Grok terminal session: %v", closeErr)
		}
	}()

	def, err := NewRuntimeDefinition(FamilyGrok, "grok-gate", "", executable, "", "grok-gate", []string{executable}, nil, neutralCWD.String(), 2*time.Minute)
	if err != nil {
		_ = launchDir.Close()
		t.Fatal(err)
	}
	packet, err := ports.NewProviderPacketFromBytes([]byte(`Reply with ONLY the exact JSON object {"status":"MULGAE_GROK_TERMINAL_OK"}.`))
	if err != nil {
		_ = launchDir.Close()
		t.Fatal(err)
	}
	grokCred, err := ports.NewAnchoredRoot(filepath.Join(nativeHome.String(), ".grok"))
	if err != nil {
		_ = launchDir.Close()
		t.Fatal(err)
	}
	cpRoots, cpLiterals, err := defaultControlPlanePathsForHome(nativeHome)
	if err != nil {
		_ = launchDir.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := executeTerminalInvocation(ctx, session, grokTerminalProfile{}, terminalDriverRequest{
		Definition:           def,
		Purpose:              terminalPurposeQualification,
		Packet:               packet,
		NamespaceRoot:        lease.root,
		NamespaceEnvironment: lease.Environment(),
		NeutralCWD:           neutralCWD,
		LaunchDirectory:      launchDir,
		NativeHome:           nativeHome,
		SourceRoot:           neutralCWD,
		ReadOnlyRoots:        []ports.AnchoredRoot{neutralCWD},
		CredentialRoots:      []ports.AnchoredRoot{grokCred},
		ControlPlaneRoots:    cpRoots,
		ControlPlaneLiterals: cpLiterals,
		Timeout:              2 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Grok terminal smoke failed: %v", err)
	}
	if !res.Process.TerminalSessionCompleted() {
		t.Fatalf("Grok terminal process did not complete cleanly: %#v", res.Process)
	}
	if !strings.Contains(string(res.OutputBytes), "MULGAE_GROK_TERMINAL_OK") {
		t.Fatalf("Grok terminal output = %q", res.OutputBytes)
	}
}

func TestLiveGrokTerminalCancellationDrainsOnlyItsProcessGroup(t *testing.T) {
	executable, err := filepath.EvalSymlinks(filepath.Join(mustLiveGrokHome(t), ".grok", "bin", "grok"))
	if err != nil {
		t.Fatal(err)
	}
	nativeHome, err := ports.NewAnchoredRoot(mustLiveGrokHome(t))
	if err != nil {
		t.Fatal(err)
	}
	launchDir, neutralCWD, err := openNeutralQualificationDirectory(nativeHome.String())
	if err != nil {
		t.Fatal(err)
	}
	lease := mustLiveGrokNamespace(t)
	namespaceRoot := lease.root

	session, err := herdradapter.NewSession(herdradapter.SessionOptions{
		Clock:         runtimeadapter.SystemClock{},
		LaunchBuilder: processadapter.NewPaneLaunchBuilder(),
		NativeHome:    nativeHome,
	})
	if err != nil {
		_ = launchDir.Close()
		drainLiveGrokNamespace(t, lease)
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if closeErr := session.Close(cleanupCtx); closeErr != nil {
			t.Errorf("close Grok terminal session: %v", closeErr)
		}
	}()

	def, err := NewRuntimeDefinition(FamilyGrok, "grok-gate", "", executable, "", "grok-gate", []string{executable}, nil, neutralCWD.String(), 2*time.Minute)
	if err != nil {
		_ = launchDir.Close()
		drainLiveGrokNamespace(t, lease)
		t.Fatal(err)
	}
	packet, err := ports.NewProviderPacketFromBytes([]byte("Think carefully for sixty seconds before writing the JSON response."))
	if err != nil {
		_ = launchDir.Close()
		drainLiveGrokNamespace(t, lease)
		t.Fatal(err)
	}
	grokCred, err := ports.NewAnchoredRoot(filepath.Join(nativeHome.String(), ".grok"))
	if err != nil {
		_ = launchDir.Close()
		drainLiveGrokNamespace(t, lease)
		t.Fatal(err)
	}
	cpRoots, cpLiterals, err := defaultControlPlanePathsForHome(nativeHome)
	if err != nil {
		_ = launchDir.Close()
		drainLiveGrokNamespace(t, lease)
		t.Fatal(err)
	}
	unrelated := exec.Command("/bin/sleep", "20")
	unrelated.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := unrelated.Start(); err != nil {
		_ = launchDir.Close()
		drainLiveGrokNamespace(t, lease)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unrelated.Process.Kill(); _, _ = unrelated.Process.Wait() })

	warmCtx, warmCancel := context.WithTimeout(context.Background(), 30*time.Second)
	if _, warmErr := session.RuntimeIdentity(warmCtx); warmErr != nil {
		warmCancel()
		_ = launchDir.Close()
		drainLiveGrokNamespace(t, lease)
		t.Fatalf("warm herdr-core session before cancel test: %v", warmErr)
	}
	warmCancel()

	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(3*time.Second, cancel)
	res, runErr := executeTerminalInvocation(ctx, session, grokTerminalProfile{}, terminalDriverRequest{
		Definition:           def,
		Purpose:              terminalPurposeQualification,
		Packet:               packet,
		NamespaceRoot:        lease.root,
		NamespaceEnvironment: lease.Environment(),
		NeutralCWD:           neutralCWD,
		LaunchDirectory:      launchDir,
		NativeHome:           nativeHome,
		SourceRoot:           neutralCWD,
		ReadOnlyRoots:        []ports.AnchoredRoot{neutralCWD},
		CredentialRoots:      []ports.AnchoredRoot{grokCred},
		ControlPlaneRoots:    cpRoots,
		ControlPlaneLiterals: cpLiterals,
		Timeout:              2 * time.Minute,
	})
	timer.Stop()
	cancel()
	if runErr == nil || res.Process.Termination() != ports.ProcessTerminationCancelled {
		t.Fatalf("cancelled Grok terminal = termination %q error %v", res.Process.Termination(), runErr)
	}
	lifecycle, ok := res.Process.LifecycleReceipt()
	if !ok || !lifecycle.ProcessGroupAbsent() {
		t.Fatalf("cancelled Grok terminal process group was not drained: %#v", lifecycle)
	}
	if err := unrelated.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("unrelated process was disturbed: %v", err)
	}
	drainLiveGrokNamespace(t, lease)
	if _, err := os.Lstat(namespaceRoot); !os.IsNotExist(err) {
		t.Fatalf("Grok namespace survived cancellation cleanup: %v", err)
	}
}

func TestLiveGrokTerminalVersionAndExecutableIdentity(t *testing.T) {
	source, err := filepath.EvalSymlinks(filepath.Join(mustLiveGrokHome(t), ".grok", "bin", "grok"))
	if err != nil {
		t.Fatal(err)
	}
	copied := copyLiveGrokExecutable(t, source)
	sourceBytes, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	copyBytes, err := os.ReadFile(copied)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(sourceBytes) != sha256.Sum256(copyBytes) {
		t.Fatal("qualified and execution Grok binaries differ")
	}
	output, err := exec.Command(copied, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("Grok --version failed: %q, %v", output, err)
	}
	version, ok := parseGrokVersionOutput(string(output))
	if !ok || !VersionAtLeast(version, 1, 0, 89) {
		t.Fatalf("Grok version = %q (parsed %q, ok=%t), want >= 1.0.89", output, version, ok)
	}
}

func parseGrokVersionOutput(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	matches := grokVersionOutput.FindStringSubmatch(trimmed)
	if len(matches) != 2 {
		return "", false
	}
	return matches[1], true
}

func copyLiveGrokExecutable(t *testing.T, sourcePath string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(resolved)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	destination := filepath.Join(mustCanonicalLiveTempDir(t), "grok")
	target, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(target, source); err != nil {
		_ = target.Close()
		t.Fatal(err)
	}
	if err := target.Sync(); err != nil {
		_ = target.Close()
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	return destination
}

func mustLiveGrokHome(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func mustCanonicalLiveTempDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func mustLiveGrokNamespace(t *testing.T) *namespaceLease {
	t.Helper()
	nativeHome := mustLiveGrokHome(t)
	base, err := NewNamespaceFactory(mustCanonicalLiveTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := RuntimeSafetyPolicyForFamily(CredentialSourceGrok)
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewCredentialProjectingNamespaceFactoryWithPolicies(
		base, nativeHome,
		map[string]CredentialSourceFamily{"grok-gate": CredentialSourceGrok},
		map[string]RuntimeSafetyPolicy{"grok-gate": policy},
	)
	if err != nil {
		t.Fatal(err)
	}
	acquired, err := factory.AcquireProviderNamespace(context.Background(), "grok-gate", FamilyGrok)
	if err != nil {
		t.Fatal(err)
	}
	lease, ok := acquired.(*namespaceLease)
	if !ok {
		t.Fatal("Grok namespace has an unexpected implementation")
	}
	return lease
}

func drainLiveGrokNamespace(t *testing.T, lease *namespaceLease) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := lease.DrainTerminal(ctx); err != nil {
		t.Errorf("drain Grok namespace: %v", err)
	}
}
