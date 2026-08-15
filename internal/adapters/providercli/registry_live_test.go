//go:build liveprovider && darwin && arm64

package providercli_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	environmentadapter "github.com/irootkernel/mulgae/internal/adapters/environment"
	filesystemadapter "github.com/irootkernel/mulgae/internal/adapters/filesystem"
	processadapter "github.com/irootkernel/mulgae/internal/adapters/process"
	"github.com/irootkernel/mulgae/internal/adapters/providercli"
	runtimeadapter "github.com/irootkernel/mulgae/internal/adapters/runtime"
	workspaceadapter "github.com/irootkernel/mulgae/internal/adapters/workspace"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type liveCapabilityConfig struct {
	family         string
	credential     providercli.CredentialSourceFamily
	instance       string
	role           domain.Role
	executableEnv  string
	launcherEnv    string
	dataHomeEnv    string
	transportIndex int
	transport      ports.ProviderPacketChannel
	minimumVersion [3]int
	kimiModel      string
	protectedPaths func(string, string) []string
}

func TestLiveKimiCapability(t *testing.T) {
	certifyLiveCapability(t, liveCapabilityConfig{
		family: providercli.FamilyKimi, credential: providercli.CredentialSourceKimi, instance: "kimi-logic", role: domain.RoleLogic,
		executableEnv: "MULGAE_LIVE_KIMI_BIN", dataHomeEnv: "MULGAE_LIVE_KIMI_DATA_HOME", transportIndex: 4,
		minimumVersion: [3]int{0, 23, 6}, kimiModel: "kimi-code/kimi-for-coding",
		protectedPaths: func(_ string, dataHome string) []string {
			return []string{filepath.Join(dataHome, "config.toml"), filepath.Join(dataHome, "credentials", "kimi-code.json")}
		},
	})
}

func TestLiveZCodeCapability(t *testing.T) {
	certifyLiveCapability(t, liveCapabilityConfig{
		family: providercli.FamilyZcode, credential: providercli.CredentialSourceZCode, instance: "zcode-security", role: domain.RoleSecurity,
		executableEnv: "MULGAE_LIVE_ZCODE_NODE_BIN", launcherEnv: "MULGAE_LIVE_ZCODE_LAUNCHER", transportIndex: 6,
		minimumVersion: [3]int{0, 15, 2},
		protectedPaths: func(home, _ string) []string {
			return []string{filepath.Join(home, ".zcode", "cli", "config.json")}
		},
	})
}

func TestLiveCodexCapability(t *testing.T) {
	certifyLiveCapability(t, liveCapabilityConfig{
		family: providercli.FamilyCodex, credential: providercli.CredentialSourceCodex, instance: "codex-logic", role: domain.RoleLogic,
		executableEnv: "MULGAE_LIVE_CODEX_BIN", transport: ports.ProviderPacketChannelStdin, transportIndex: -1,
		minimumVersion: [3]int{0, 147, 0},
		protectedPaths: func(home, _ string) []string {
			return []string{filepath.Join(home, ".codex", "auth.json")}
		},
	})
}

// liveProbeFailureMessage classifies a live capability-probe error so an
// operator can tell a throttled or unauthenticated provider account from a real
// contract violation, and knows what to do about it.
//
// It never downgrades the outcome to a skip. This suite is the release gate for
// provider certification, and a silently skipped certification is not a
// certification: a permanently throttled account would look green forever. The
// failure stays a failure; only the guidance changes.
func liveProbeFailureMessage(subject string, err error) string {
	var failure *domain.Failure
	if !errors.As(err, &failure) {
		return fmt.Sprintf("INCONCLUSIVE: %s: %v", subject, err)
	}
	switch failure.Class() {
	case domain.FailureRateLimit:
		return fmt.Sprintf("INCONCLUSIVE: %s: the provider account is rate limited (%v). "+
			"Certification did not run and this build is uncertified. "+
			"Wait for the provider's rate-limit window to reset, then run this suite again.", subject, err)
	case domain.FailureQuota:
		return fmt.Sprintf("INCONCLUSIVE: %s: the provider account has no quota left (%v). "+
			"Certification did not run and this build is uncertified. "+
			"Restore quota on the provider account, then run this suite again.", subject, err)
	case domain.FailureAuthentication:
		return fmt.Sprintf("INCONCLUSIVE: %s: the provider account is not authenticated (%v). "+
			"Certification did not run and this build is uncertified. "+
			"Log in to the provider CLI, then run this suite again.", subject, err)
	case domain.FailureTimeout:
		return fmt.Sprintf("INCONCLUSIVE: %s: the provider did not answer in time (%v). "+
			"Certification did not run and this build is uncertified. "+
			"Retry when the provider is responsive; if it persists, treat it as a provider defect.", subject, err)
	case domain.FailureInvalidOutput:
		return fmt.Sprintf("FAIL: %s: the provider answered but did not satisfy capability certification (%v). "+
			"Under heavy load this provider can answer poorly, so retry once before treating it as a defect; "+
			"a repeatable failure means this provider version no longer meets the capability contract.", subject, err)
	default:
		return fmt.Sprintf("FAIL: %s: %v", subject, err)
	}
}

func certifyLiveCapability(t *testing.T, config liveCapabilityConfig) {
	t.Helper()
	installed, err := user.Current()
	if err != nil || installed == nil {
		t.Fatalf("%s installed-user identity is unavailable: %v", config.family, err)
	}
	runtimeHome := liveCapabilityDirectory(t, "installed user home", installed.HomeDir)
	executable := liveCapabilityFile(t, config.executableEnv, true)
	launcher := ""
	if config.launcherEnv != "" {
		launcher = liveCapabilityFile(t, config.launcherEnv, false)
	}
	dataHome := ""
	if config.dataHomeEnv != "" {
		dataHome = liveCapabilityDirectory(t, config.dataHomeEnv, os.Getenv(config.dataHomeEnv))
	}
	protectedBefore := liveCapabilityManifest(t, config.protectedPaths(runtimeHome, dataHome))

	workspaceRoot := liveCapabilityTempDir(t)
	anchoredWorkspace, err := ports.NewAnchoredRoot(workspaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	materializer, err := workspaceadapter.NewMaterializer(anchoredWorkspace, filesystemadapter.NewContentDetector())
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := providercli.NewProbeFixtureLeaseFactory(materializer, providercli.SecureProbeNonceGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	fixture, err := fixtures.Acquire(ctx, config.role)
	if err != nil {
		t.Fatalf("%s immutable capability fixture: %v", config.family, err)
	}
	workspaceDrained := false
	t.Cleanup(func() {
		if workspaceDrained {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = fixture.DrainTerminal(cleanupCtx)
	})

	policy, err := providercli.RuntimeSafetyPolicyForFamily(config.credential)
	if err != nil {
		t.Fatal(err)
	}
	namespaceRoot := liveCapabilityTempDir(t)
	baseNamespaces, err := providercli.NewNamespaceFactory(namespaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	families := map[string]providercli.CredentialSourceFamily{config.instance: config.credential}
	policies := map[string]providercli.RuntimeSafetyPolicy{config.instance: policy}
	sourceRoots := map[string]string{}
	if config.credential == providercli.CredentialSourceKimi {
		sourceRoots[config.instance] = dataHome
	}
	projectedNamespaces, err := providercli.NewCredentialProjectingNamespaceFactoryWithConfiguredSourceRoots(
		baseNamespaces, runtimeHome, families, policies, nil, sourceRoots,
	)
	if err != nil {
		t.Fatalf("%s credential namespace: %v", config.family, err)
	}

	executableSHA := liveCapabilitySHA256(t, executable)
	launcherSHA := executableSHA
	baseArgv := []string{executable}
	if launcher != "" {
		launcherSHA = liveCapabilitySHA256(t, launcher)
		baseArgv = append(baseArgv, launcher)
	} else {
		launcher = executable
	}
	transportChannel := config.transport
	if transportChannel == "" {
		transportChannel = ports.ProviderPacketChannelArgvLiteral
	}
	definitionPort, err := (providercli.RuntimeBuilder{}).BuildProductionRuntime(ports.ProviderRuntimeSpec{
		Family: config.family, Instance: config.instance, Executable: executable, ExecutableSHA256: executableSHA,
		Launcher: launcher, LauncherSHA256: launcherSHA, ProfileID: config.instance,
		ProfileGeneration: "live-family-capability-v1", RuntimeSafetyPolicyIdentity: policy.Identity(), KimiModel: config.kimiModel,
		BaseArgv: baseArgv, TransportChannel: transportChannel, TransportArgvIndex: config.transportIndex,
		WorkingDirectory: "/private/var/empty", Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("%s production runtime definition: %v", config.family, err)
	}
	definition, ok := definitionPort.(providercli.RuntimeDefinition)
	if !ok {
		t.Fatalf("%s runtime builder returned an unexpected definition", config.family)
	}

	runner, err := processadapter.NewRunner(runtimeadapter.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	recording := &liveCapabilityRecordingRunner{runner: runner}
	verifier := environmentadapter.NewSpawnVerifier()
	registry, err := providercli.NewProductionRegistry(recording, projectedNamespaces, verifier, definition)
	if err != nil {
		t.Fatalf("%s production registry: %v", config.family, err)
	}
	registryDrained := false
	t.Cleanup(func() {
		if registryDrained {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = registry.Close(cleanupCtx)
	})
	namespace, ok := registry.QualificationNamespace(config.instance)
	if !ok {
		t.Fatalf("%s qualification namespace is unavailable", config.family)
	}
	probe, err := providercli.NewCurrentProbe(recording, verifier)
	if err != nil {
		t.Fatal(err)
	}
	result, err := probe.QualifyCurrent(ctx, providercli.CurrentProbeRequest{
		Definition: definition, Namespace: namespace, Fixture: fixture, Invocation: providercli.NativeProbeInvocation{},
		Now: time.Now().UTC(), TTL: time.Minute,
	})
	if err != nil {
		if count := len(recording.observations); count > 0 {
			observation := recording.observations[count-1]
			exitCode, exited := observation.ExitCode()
			t.Logf("%s failed observation: launches=%d termination=%s exited=%t exit_code=%d stdout_bytes=%d stderr_bytes=%d stdin_complete=%t",
				config.family, count, observation.Termination(), exited, exitCode, len(observation.Stdout()), len(observation.Stderr()), observation.StdinWriteReceipt().Complete())
		}
		t.Fatal(liveProbeFailureMessage(string(config.family)+" live capability certification", err))
	}
	if !providercli.VersionAtLeast(result.Version, config.minimumVersion[0], config.minimumVersion[1], config.minimumVersion[2]) {
		t.Fatalf("%s version %q is below the supported minimum", config.family, result.Version)
	}
	if len(recording.requests) != 2 || len(recording.observations) != 2 {
		t.Fatalf("%s launches = requests:%d observations:%d, want one version and one capability", config.family, len(recording.requests), len(recording.observations))
	}
	for _, request := range recording.requests {
		if request.WorkingDirectory() != fixture.WorkspaceSnapshotIdentity().SnapshotPath() {
			t.Fatalf("%s launch escaped the immutable capability fixture", config.family)
		}
	}
	transport, ok := recording.observations[1].ProviderPacketTransportReceipt()
	if !ok || !transport.Valid() || transport.Channel() != transportChannel {
		t.Fatalf("%s capability transport receipt is invalid", config.family)
	}
	liveCapabilityRequireReceipts(t, config.family, result.Receipts)

	workspaceReceipt, err := fixture.DrainTerminal(ctx)
	if err != nil || !workspaceReceipt.Valid() {
		t.Fatalf("%s capability workspace did not drain: %v", config.family, err)
	}
	runReceipt, err := registry.Close(ctx)
	if err != nil || !runReceipt.Valid() {
		t.Fatalf("%s capability namespace did not drain: %v", config.family, err)
	}
	for _, receipt := range runReceipt.NamespaceReceipts() {
		if !receipt.Drained() || !receipt.Unlinked() || !receipt.TornDown() {
			t.Fatalf("%s namespace terminal receipt is incomplete", config.family)
		}
	}
	protectedAfter := liveCapabilityManifest(t, config.protectedPaths(runtimeHome, dataHome))
	if !reflect.DeepEqual(protectedBefore, protectedAfter) {
		t.Fatalf("%s certification changed protected native credential/settings state", config.family)
	}
	workspaceDrained = true
	registryDrained = true
	t.Logf("PASS: %s %s completed one production-boundary capability certification", config.family, result.Version)
}

func liveCapabilityRequireReceipts(t *testing.T, family string, receipts []providercli.CurrentProbeReceipt) {
	t.Helper()
	want := map[string]bool{
		"workspace": true, "manifest": true, "namespace": true, "environment": true, "transport": true,
		"native-reference": true, "version": true, "capability": true, "base-role": true, "assignment": true,
		"direct-execution-authority": true,
	}
	if len(receipts) != len(want) {
		t.Fatalf("%s capability receipt count = %d, want %d", family, len(receipts), len(want))
	}
	for _, receipt := range receipts {
		if !want[receipt.Kind] || receipt.EvidenceID == "" || receipt.ExpiresAt.IsZero() {
			t.Fatalf("%s capability receipt is invalid: %#v", family, receipt)
		}
		delete(want, receipt.Kind)
	}
	if len(want) != 0 {
		t.Fatalf("%s capability receipts are incomplete: %v", family, want)
	}
}

type liveCapabilityRecordingRunner struct {
	runner       ports.ProcessRunner
	requests     []ports.ProcessRequest
	observations []ports.ProcessObservation
}

func (runner *liveCapabilityRecordingRunner) Run(ctx context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	runner.requests = append(runner.requests, request)
	observation, err := runner.runner.Run(ctx, request)
	runner.observations = append(runner.observations, observation)
	return observation, err
}

type liveCapabilityFileState struct {
	path     string
	mode     os.FileMode
	size     int64
	modified int64
	sha256   string
}

func liveCapabilityManifest(t *testing.T, paths []string) []liveCapabilityFileState {
	t.Helper()
	states := make([]liveCapabilityFileState, 0, len(paths))
	for _, path := range paths {
		canonical := liveCapabilityFilePath(t, path, false)
		info, err := os.Lstat(canonical)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("protected live capability file is unavailable: %v", err)
		}
		states = append(states, liveCapabilityFileState{
			path: canonical, mode: info.Mode(), size: info.Size(), modified: info.ModTime().UnixNano(), sha256: liveCapabilitySHA256(t, canonical),
		})
	}
	return states
}

func liveCapabilityFile(t *testing.T, environmentName string, executable bool) string {
	t.Helper()
	value := os.Getenv(environmentName)
	if value == "" {
		t.Fatalf("%s is required", environmentName)
	}
	return liveCapabilityFilePath(t, value, executable)
}

func liveCapabilityFilePath(t *testing.T, value string, executable bool) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(value)
	if err != nil || !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		t.Fatalf("live capability file %q is not canonical: %v", value, err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || executable && info.Mode()&0o111 == 0 {
		t.Fatalf("live capability file %q is unavailable or has the wrong mode: %v", resolved, err)
	}
	return resolved
}

func liveCapabilityDirectory(t *testing.T, label, value string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(value)
	if err != nil || !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		t.Fatalf("%s is not a canonical directory: %v", label, err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		t.Fatalf("%s is unavailable: %v", label, err)
	}
	return resolved
}

func liveCapabilitySHA256(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		t.Fatal(err)
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func liveCapabilityTempDir(t *testing.T) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}
