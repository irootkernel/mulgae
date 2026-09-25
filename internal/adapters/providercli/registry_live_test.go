//go:build liveprovider && darwin && arm64

package providercli_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	environmentadapter "github.com/irootkernel/mulgae/internal/adapters/environment"
	filesystemadapter "github.com/irootkernel/mulgae/internal/adapters/filesystem"
	processadapter "github.com/irootkernel/mulgae/internal/adapters/process"
	"github.com/irootkernel/mulgae/internal/adapters/providercli"
	runtimeadapter "github.com/irootkernel/mulgae/internal/adapters/runtime"
	workspaceadapter "github.com/irootkernel/mulgae/internal/adapters/workspace"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type liveCapabilityConfig struct {
	family         string
	credential     providercli.CredentialSourceFamily
	instance       string
	role           domain.Role
	appBundleEnv   string
	executableEnv  string
	dataHomeEnv    string
	transportIndex int
	transport      ports.ProviderPacketChannel
	minimumVersion [3]int
	protectedPaths func(string, string) []string
}

func TestMain(m *testing.M) {
	handled, err := processadapter.ExecInheritedDirectory(os.Args)
	if handled {
		if err != nil {
			os.Exit(125)
		}
		os.Exit(126)
	}
	os.Exit(m.Run())
}

func TestLiveZCodeCapability(t *testing.T) {
	config := liveCapabilityConfig{
		family: providercli.FamilyZcode, credential: providercli.CredentialSourceZCode, instance: "zcode-security", role: domain.RoleSecurity,
		appBundleEnv: "MULGAE_LIVE_ZCODE_APP_BUNDLE", transport: ports.ProviderPacketChannelProtocol, transportIndex: -1,
		minimumVersion: [3]int{0, 16, 5},
		protectedPaths: func(home, _ string) []string {
			return []string{filepath.Join(home, ".zcode", "v2", "setting.json"), filepath.Join(home, ".zcode", "v2", "credentials.json")}
		},
	}
	if err := certifyLiveCapability(t, config); err != nil {
		t.Fatal(liveProbeFailureMessage("zcode live capability certification", err))
	}
}

func TestLiveGrokCapability(t *testing.T) {
	config := liveCapabilityConfig{
		family: providercli.FamilyGrok, credential: providercli.CredentialSourceGrok, instance: "grok-logic", role: domain.RoleLogic,
		executableEnv: "MULGAE_LIVE_GROK_BIN", transport: ports.ProviderPacketChannelProtocol, transportIndex: -1,
		minimumVersion: [3]int{1, 0, 30},
		protectedPaths: func(home, _ string) []string {
			return []string{filepath.Join(home, ".grok", "auth.json")}
		},
	}
	if err := certifyLiveCapability(t, config); err != nil {
		t.Fatal(liveProbeFailureMessage("grok live capability certification", err))
	}
}

func TestLiveCodexCapability(t *testing.T) {
	config := liveCapabilityConfig{
		family: providercli.FamilyCodex, credential: providercli.CredentialSourceCodex, instance: "codex-logic", role: domain.RoleLogic,
		executableEnv: "MULGAE_LIVE_CODEX_BIN", dataHomeEnv: "MULGAE_LIVE_CODEX_HOME", transport: ports.ProviderPacketChannelProtocol, transportIndex: -1,
		minimumVersion: [3]int{0, 154, 0},
		protectedPaths: func(_ string, dataHome string) []string {
			return []string{filepath.Join(dataHome, "auth.json")}
		},
	}
	err := certifyLiveCapability(t, config)
	if err == nil {
		t.Logf("codex selected credential profile: primary=%s", liveCodexCredentialHomeLabel(os.Getenv(config.dataHomeEnv)))
		return
	}
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureQuota {
		t.Fatal(liveProbeFailureMessage("codex live capability certification", err))
	}
	if os.Getenv("MULGAE_LIVE_CODEX_FALLBACK_HOME") == "" {
		t.Fatal("INCONCLUSIVE: codex live capability certification: the primary account has no quota and no fallback credential home is configured. Set MULGAE_E2E_CODEX_FALLBACK_HOME for make test-e2e, or MULGAE_LIVE_CODEX_FALLBACK_HOME when running this suite directly, to an absolute authenticated Codex home, then run the check again.")
	}
	t.Log("codex primary credential home has no quota; retrying capability certification with the configured fallback home")
	config.dataHomeEnv = "MULGAE_LIVE_CODEX_FALLBACK_HOME"
	if fallbackErr := certifyLiveCapability(t, config); fallbackErr != nil {
		t.Fatal(liveProbeFailureMessage("codex fallback live capability certification", fallbackErr))
	}
	t.Logf("codex selected credential profile: quota_fallback=%s", liveCodexCredentialHomeLabel(os.Getenv(config.dataHomeEnv)))
}

func liveCodexCredentialHomeLabel(value string) string {
	if value == "" {
		return "<unset>"
	}
	home, err := os.UserHomeDir()
	if err == nil {
		switch filepath.Clean(value) {
		case filepath.Join(home, ".codex"):
			return "~/.codex"
		case filepath.Join(home, ".codex-hsy"):
			return "~/.codex-hsy"
		}
	}
	return "<custom>"
}

func TestLiveCodexCredentialHomeLabel(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		value string
		want  string
	}{
		{value: "", want: "<unset>"},
		{value: filepath.Join(home, ".codex"), want: "~/.codex"},
		{value: filepath.Join(home, ".codex-hsy"), want: "~/.codex-hsy"},
		{value: filepath.Join(home, ".codex-secondary"), want: "<custom>"},
		{value: filepath.Join(home, "private-codex-profile"), want: "<custom>"},
	} {
		if got := liveCodexCredentialHomeLabel(test.value); got != test.want {
			t.Fatalf("liveCodexCredentialHomeLabel(%q) = %q, want %q", test.value, got, test.want)
		}
	}
}

func TestLiveCodexCredentialPathDiagnosticsRedactNativePaths(t *testing.T) {
	privateRoot := t.TempDir()
	privateFile := filepath.Join(privateRoot, "auth.json")
	if err := os.WriteFile(privateFile, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name   string
		value  string
		file   bool
		reason string
	}{
		{name: "missing credential file", value: filepath.Join(privateRoot, "missing-auth.json"), file: true, reason: "is not canonical"},
		{name: "credential file is a directory", value: privateRoot, file: true, reason: "is unavailable or has the wrong mode"},
		{name: "relative credential file", value: "private-auth.json", file: true, reason: "is not canonical"},
		{name: "missing credential home", value: filepath.Join(privateRoot, "missing-home"), reason: "is not a canonical directory"},
		{name: "credential home is a file", value: privateFile, reason: "is unavailable"},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			var reason string
			if check.file {
				_, reason = resolveLiveCapabilityFile(check.value, false)
			} else {
				_, reason = resolveLiveCapabilityDirectory(check.value)
			}
			if reason != check.reason {
				t.Fatalf("reason = %q, want %q", reason, check.reason)
			}
			if strings.Contains(reason, privateRoot) || strings.Contains(reason, check.value) {
				t.Fatalf("diagnostic disclosed a native credential path: %q", reason)
			}
		})
	}
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
			"Inspect the preserved private request and response to distinguish a provider mismatch from a Mulgae decoding defect. "+
			"A successful retry alone does not establish stability.", subject, err)
	default:
		return fmt.Sprintf("FAIL: %s: %v", subject, err)
	}
}

func certifyLiveCapability(t *testing.T, config liveCapabilityConfig) error {
	t.Helper()
	installed, err := user.Current()
	if err != nil || installed == nil {
		t.Fatalf("%s installed-user identity is unavailable: %v", config.family, err)
	}
	runtimeHome := liveCapabilityDirectory(t, "installed user home", installed.HomeDir)
	executable := ""
	launcher := ""
	zcodeProviderConfig := ""
	applicationVersion := ""
	applicationMetadata := ""
	applicationMetadataSHA := ""
	if config.appBundleEnv != "" {
		appBundle := liveCapabilityDirectory(t, config.appBundleEnv, os.Getenv(config.appBundleEnv))
		profile, discoverErr := reviewrun.DiscoverProviderProfileWithOverride(context.Background(), environmentadapter.NewInspector(), reviewrun.FamilyZCode, appBundle)
		if discoverErr != nil || profile.Executable() == "" || profile.Launcher() == "" || profile.ZCodeProviderConfig() == "" || profile.ApplicationVersion() == "" || profile.ApplicationMetadata() == "" || profile.ApplicationMetadataSHA256() == "" {
			t.Fatalf("%s production ZCode discovery: reason=%q error=%v", config.family, profile.Reason(), discoverErr)
		}
		executable, launcher, zcodeProviderConfig = profile.Executable(), profile.Launcher(), profile.ZCodeProviderConfig()
		applicationVersion, applicationMetadata, applicationMetadataSHA = profile.ApplicationVersion(), profile.ApplicationMetadata(), profile.ApplicationMetadataSHA256()
	} else {
		executable = liveCapabilityFile(t, config.executableEnv, true)
	}
	dataHome := ""
	if config.dataHomeEnv != "" {
		dataHome = liveCapabilityDirectory(t, config.dataHomeEnv, os.Getenv(config.dataHomeEnv))
	}
	protectedBefore := liveCapabilityManifest(t, config.family+" protected credential/settings file", config.protectedPaths(runtimeHome, dataHome))

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
	ctx, cancel := context.WithTimeout(context.Background(), 190*time.Second)
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
	if config.credential == providercli.CredentialSourceCodex {
		sourceRoots[config.instance] = dataHome
	}
	var projectedNamespaces ports.ProviderNamespaceFactory
	if config.credential == providercli.CredentialSourceGrok {
		projectedNamespaces, err = providercli.NewCredentialProjectingNamespaceFactoryWithProjectRoot(
			baseNamespaces, runtimeHome, liveCapabilityTempDir(t), families, policies, nil, sourceRoots,
		)
	} else {
		projectedNamespaces, err = providercli.NewCredentialProjectingNamespaceFactoryWithConfiguredSourceRoots(
			baseNamespaces, runtimeHome, families, policies, nil, sourceRoots,
		)
	}
	if err != nil {
		t.Fatalf("%s credential namespace: %v", config.family, err)
	}

	executableSHA := liveCapabilitySHA256(t, "provider executable", executable)
	launcherSHA := executableSHA
	zcodeProviderConfigSHA := ""
	baseArgv := []string{executable}
	if launcher != "" {
		launcherSHA = liveCapabilitySHA256(t, "provider launcher", launcher)
		zcodeProviderConfigSHA = liveCapabilitySHA256(t, "ZCode built-in provider config", zcodeProviderConfig)
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
		ZCodeProviderConfig: zcodeProviderConfig, ZCodeProviderConfigSHA256: zcodeProviderConfigSHA,
		ApplicationVersion: applicationVersion, ApplicationMetadata: applicationMetadata, ApplicationMetadataSHA256: applicationMetadataSHA,
		ProfileGeneration: "live-family-capability-v1", RuntimeSafetyPolicyIdentity: policy.Identity(),
		BaseArgv: baseArgv, TransportChannel: transportChannel, TransportArgvIndex: config.transportIndex,
		WorkingDirectory: "/private/var/empty", Timeout: 3 * time.Minute,
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
		preserveLiveCapabilityFailure(t, config.family, fixture.Packet(), recording.observations)
		if count := len(recording.observations); count > 0 {
			observation := recording.observations[count-1]
			exitCode, exited := observation.ExitCode()
			t.Logf("%s failed observation: launches=%d termination=%s exited=%t exit_code=%d stdout_bytes=%d stderr_bytes=%d stdin_complete=%t",
				config.family, count, observation.Termination(), exited, exitCode, len(observation.Stdout()), len(observation.Stderr()), observation.StdinWriteReceipt().Complete())
		}
		protectedAfter := liveCapabilityManifest(t, config.family+" protected credential/settings file", config.protectedPaths(runtimeHome, dataHome))
		if !reflect.DeepEqual(protectedBefore, protectedAfter) {
			t.Fatalf("%s certification changed protected native credential/settings state", config.family)
		}
		return err
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
	protectedAfter := liveCapabilityManifest(t, config.family+" protected credential/settings file", config.protectedPaths(runtimeHome, dataHome))
	if !reflect.DeepEqual(protectedBefore, protectedAfter) {
		t.Fatalf("%s certification changed protected native credential/settings state", config.family)
	}
	workspaceDrained = true
	registryDrained = true
	t.Logf("PASS: %s %s completed one production-boundary capability certification", config.family, result.Version)
	return nil
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

// Converse carries protocol-channel routes through the same recording so live
// zcode certification exercises the real conversation runner.
func (runner *liveCapabilityRecordingRunner) Converse(ctx context.Context, request ports.ProcessRequest, driver ports.ProviderSessionDriver) (ports.ProcessObservation, error) {
	conversationRunner, ok := runner.runner.(ports.ProviderConversationRunner)
	if !ok {
		return ports.ProcessObservation{}, fmt.Errorf("live capability recording runner cannot converse")
	}
	runner.requests = append(runner.requests, request)
	observation, err := conversationRunner.Converse(ctx, request, driver)
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

func liveCapabilityManifest(t *testing.T, label string, paths []string) []liveCapabilityFileState {
	t.Helper()
	states := make([]liveCapabilityFileState, 0, len(paths))
	for _, path := range paths {
		canonical := liveCapabilityFilePath(t, label, path, false)
		info, err := os.Lstat(canonical)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("%s is unavailable or has the wrong mode", label)
		}
		states = append(states, liveCapabilityFileState{
			path: canonical, mode: info.Mode(), size: info.Size(), modified: info.ModTime().UnixNano(), sha256: liveCapabilitySHA256(t, label, canonical),
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
	return liveCapabilityFilePath(t, environmentName, value, executable)
}

func liveCapabilityFilePath(t *testing.T, label, value string, executable bool) string {
	t.Helper()
	resolved, reason := resolveLiveCapabilityFile(value, executable)
	if reason != "" {
		t.Fatalf("live capability file %s %s", label, reason)
	}
	return resolved
}

func resolveLiveCapabilityFile(value string, executable bool) (string, string) {
	resolved, err := filepath.EvalSymlinks(value)
	if err != nil || !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		return "", "is not canonical"
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || executable && info.Mode()&0o111 == 0 {
		return "", "is unavailable or has the wrong mode"
	}
	return resolved, ""
}

func liveCapabilityDirectory(t *testing.T, label, value string) string {
	t.Helper()
	resolved, reason := resolveLiveCapabilityDirectory(value)
	if reason != "" {
		t.Fatalf("%s %s", label, reason)
	}
	return resolved
}

func resolveLiveCapabilityDirectory(value string) (string, string) {
	resolved, err := filepath.EvalSymlinks(value)
	if err != nil || !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		return "", "is not a canonical directory"
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", "is unavailable"
	}
	return resolved, ""
}

func liveCapabilitySHA256(t *testing.T, label, path string) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("%s is unreadable", label)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		t.Fatalf("%s could not be hashed", label)
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

// Failed standalone certifications outlive their disposable fixture so exact
// provider responses can be investigated without printing raw data in test logs.
func preserveLiveCapabilityFailure(t *testing.T, family string, packet []byte, observations []ports.ProcessObservation) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "mulgae-capability-failure-"+family+"-")
	if err != nil {
		t.Fatalf("create private capability diagnostics: %v", err)
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	writer := filesystemadapter.NewSecureWriter()
	write := func(name, channel string, body []byte) {
		if len(body) == 0 {
			return
		}
		destination, pathErr := ports.NewSafeRelativePath(name)
		if pathErr != nil {
			t.Fatal(pathErr)
		}
		request, requestErr := ports.NewSecureWriteRequest(root, destination, channel, bytes.NewReader(body), int64(len(body)), []string{"capability:" + family}, func(error) {})
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		_, drop, writeErr := writer.Write(context.Background(), request)
		if drop != nil {
			t.Logf("capability diagnostic stream dropped by security screening: %s", name)
			return
		}
		if writeErr != nil {
			t.Fatalf("persist capability diagnostic: %v", writeErr)
		}
	}
	write("request.txt", "provider_stdout", packet)
	for index, observation := range observations {
		prefix := fmt.Sprintf("%03d", index+1)
		write(prefix+".stdout.raw", "provider_stdout", observation.Stdout())
		write(prefix+".stderr.raw", "provider_stderr", observation.Stderr())
		exitCode, exited := observation.ExitCode()
		metadata, marshalErr := json.Marshal(struct {
			Termination ports.ProcessTermination `json:"termination"`
			Exited      bool                     `json:"exited"`
			ExitCode    int                      `json:"exit_code"`
			StdoutBytes int                      `json:"stdout_bytes"`
			StderrBytes int                      `json:"stderr_bytes"`
		}{observation.Termination(), exited, exitCode, len(observation.Stdout()), len(observation.Stderr())})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		write(prefix+".json", "runtime_diagnostic", metadata)
	}
	t.Logf("preserved private capability diagnostics: %s", directory)
	return directory
}

func TestLiveCapabilityFailureEvidenceIsPrivateAndScreened(t *testing.T) {
	now := time.Now().UTC()
	emptyHash := sha256.Sum256(nil)
	stdin, err := ports.NewStdinWriteReceipt(0, 0, hex.EncodeToString(emptyHash[:]), true)
	if err != nil {
		t.Fatal(err)
	}
	code := 0
	output := []byte(`{"response":"wrong fixture proof"}`)
	observation, err := ports.NewProcessObservation(output, []byte("KKACHI_SECRET_password=value_7f20c84d"), &code, ports.ProcessTerminationExited, stdin, now, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	packet := []byte("private capability packet")
	directory := preserveLiveCapabilityFailure(t, "zcode", packet, []ports.ProcessObservation{observation})
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	for name, want := range map[string][]byte{"request.txt": packet, "001.stdout.raw": output} {
		path := filepath.Join(directory, name)
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("retained %s = %q, err=%v", name, got, err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("private mode: %v %v", info, err)
		}
	}
	if _, err := os.Stat(filepath.Join(directory, "001.stderr.raw")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("secret response persisted: %v", err)
	}
	info, err := os.Stat(directory)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("private directory: %v %v", info, err)
	}
	metadata, err := os.ReadFile(filepath.Join(directory, "001.json"))
	if err != nil || !bytes.Contains(metadata, []byte(`"exit_code":0`)) || !bytes.Contains(metadata, []byte(`"exited":true`)) {
		t.Fatalf("missing process facts: %q %v", metadata, err)
	}
}

func TestLiveCapabilityMismatchGuidanceDoesNotInventRootCause(t *testing.T) {
	failure, err := domain.NewFailure("capability", domain.FailureInvalidOutput, "controlled evidence mismatch", nil)
	if err != nil {
		t.Fatal(err)
	}
	message := liveProbeFailureMessage("zcode certification", failure)
	if strings.Contains(message, "heavy load") || strings.Contains(message, "provider version no longer") || !strings.Contains(message, "Mulgae decoding defect") {
		t.Fatalf("misleading failure guidance: %s", message)
	}
}
