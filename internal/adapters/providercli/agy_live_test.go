//go:build liveprovider && darwin && arm64

package providercli_test

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

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

func TestLiveAgyCapability(t *testing.T) {
	binaryPath := liveAgyConfiguredPath(t, "MULGAE_LIVE_AGY_BIN")
	runtimeHome, err := liveAgyInstalledHome(user.Current, os.Geteuid(), os.Getenv("MULGAE_LIVE_AGY_HOME"))
	if err != nil {
		t.Fatalf("INCONCLUSIVE: resolve installed AGY user home: %v", err)
	}
	if !liveAgyHomeAvailable(runtimeHome) {
		t.Fatal("INCONCLUSIVE: installed AGY native home is unavailable")
	}
	if !liveAgyExecutableAvailable(binaryPath) {
		t.Fatal("INCONCLUSIVE: configured AGY executable is unavailable")
	}
	authBeforeSetup, err := liveAgyAuthSettingsManifest(runtimeHome)
	if err != nil {
		t.Fatalf("INCONCLUSIVE: capture installed AGY filesystem auth/settings before Mulgae setup: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()

	workspaceRoot, err := ports.NewAnchoredRoot(liveAgyTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	materializer, err := workspaceadapter.NewMaterializer(workspaceRoot, filesystemadapter.NewContentDetector())
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := providercli.NewProbeFixtureLeaseFactory(materializer, providercli.SecureProbeNonceGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := fixtures.Acquire(ctx, domain.RoleSecurity)
	if err != nil {
		t.Fatal("INCONCLUSIVE: acquire immutable AGY qualification fixture")
	}
	workspaceIdentity := fixture.WorkspaceSnapshotIdentity()
	var registry *providercli.Registry
	drained := false
	t.Cleanup(func() {
		if !drained {
			if _, err := fixture.DrainTerminal(context.Background()); err != nil {
				t.Error("drain AGY qualification workspace")
			}
			if registry != nil {
				if _, err := registry.Close(context.Background()); err != nil {
					t.Error("drain AGY qualification namespace")
				}
			}
		}
	})

	policy, err := providercli.RuntimeSafetyPolicyForFamilyAndWorkspaceRoot(providercli.CredentialSourceAGY, workspaceRoot.String())
	if err != nil {
		t.Fatal(err)
	}
	namespaceRoot := liveAgyTempDir(t)
	namespaceFactory, err := providercli.NewNamespaceFactory(namespaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	nativeHomeFactory, err := providercli.NewCredentialProjectingNamespaceFactoryWithPoliciesAndNativeHomes(
		namespaceFactory,
		runtimeHome,
		map[string]providercli.CredentialSourceFamily{"agy-live-current": providercli.CredentialSourceAGY},
		map[string]providercli.RuntimeSafetyPolicy{"agy-live-current": policy},
		map[string]string{"agy-live-current": runtimeHome},
	)
	if err != nil {
		t.Fatal("INCONCLUSIVE: construct AGY native-home namespace factory")
	}

	binarySHA256, err := liveAgyFileSHA256(binaryPath)
	if err != nil {
		t.Fatal("INCONCLUSIVE: hash AGY executable")
	}
	key, err := ports.ParseConcurrencyKey("agy-live-current")
	if err != nil {
		t.Fatal(err)
	}
	transport, err := providercli.NewRuntimeTransport(ports.ProviderPacketChannelArgvLiteral, 12, "")
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := ports.NewBoundedPostOutputLifecycle(ports.ProcessOutputFramingTerminalJSONObject, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	definition, err := providercli.NewProductionRuntimeDefinitionWithTransportAndSafetyPolicyAndPostOutputLifecycle(
		providercli.FamilyAgy, "agy-live-current", "", binaryPath, binarySHA256, binaryPath, binarySHA256,
		key, "agy-live-current", "live-current-v1", policy.Identity(), []string{binaryPath}, transport, lifecycle,
		nil, namespaceRoot, 30*time.Second, 64<<10, 64<<10,
	)
	if err != nil {
		t.Fatal(err)
	}
	invocation := providercli.NativeProbeInvocation{}
	argv, err := invocation.CapabilityArgv(definition, fixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(argv) == 0 {
		t.Fatal("FAIL: AGY capability invocation is empty")
	}
	for _, argument := range argv {
		lower := strings.ToLower(argument)
		if strings.Contains(lower, "danger") || strings.Contains(lower, "permission") || strings.Contains(lower, "approve") || strings.Contains(lower, "yolo") {
			t.Fatal("FAIL: unsafe AGY capability invocation")
		}
	}

	runner, err := processadapter.NewRunner(runtimeadapter.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	recordingRunner := &liveAgyRecordingRunner{runner: runner}
	verifier := environmentadapter.NewSpawnVerifier()
	registry, err = providercli.NewProductionRegistry(recordingRunner, nativeHomeFactory, verifier, definition)
	if err != nil {
		t.Fatal("INCONCLUSIVE: retain exact AGY namespace")
	}
	namespace, ok := registry.QualificationNamespace("agy-live-current")
	if !ok {
		t.Fatal("INCONCLUSIVE: exact AGY qualification namespace unavailable")
	}
	environment := liveAgyEnvironment(t, namespace.Environment())
	if environment["HOME"] != runtimeHome {
		t.Fatal("FAIL: retained AGY namespace HOME differs from the configured native home")
	}
	for _, name := range []string{"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "TMPDIR", "TMP", "TEMP", "MULGAE_PROVIDER_SCRATCH"} {
		if !liveAgyOwnedByDisposableNamespace(environment[name], namespaceRoot) {
			t.Fatalf("FAIL: retained AGY namespace %s is not disposable", name)
		}
	}
	if err := liveAgyRequireNoCopiedNativeSettings(namespaceRoot); err != nil {
		t.Fatalf("FAIL: disposable AGY namespace copied native auth/settings: %v", err)
	}
	authAfterSetup, err := liveAgyAuthSettingsManifest(runtimeHome)
	if err != nil {
		t.Fatalf("INCONCLUSIVE: capture installed AGY filesystem auth/settings after Mulgae setup: %v", err)
	}
	if !reflect.DeepEqual(authBeforeSetup, authAfterSetup) {
		t.Fatal("FAIL: Mulgae setup changed installed AGY filesystem auth/settings surfaces")
	}
	probe, err := providercli.NewCurrentProbe(recordingRunner, verifier)
	if err != nil {
		t.Fatal(err)
	}
	result, err := probe.QualifyCurrent(ctx, providercli.CurrentProbeRequest{
		Definition: definition, Namespace: namespace, Fixture: fixture, Invocation: invocation,
		Now: time.Now().UTC(), TTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("INCONCLUSIVE: installed AGY current probe failed: %v", err)
	}
	if len(recordingRunner.observations) != 2 || len(recordingRunner.requests) != 2 {
		t.Fatalf("INCONCLUSIVE: descriptor-bound AGY launches = observations:%d requests:%d, want version and capability launches", len(recordingRunner.observations), len(recordingRunner.requests))
	}
	for _, request := range recordingRunner.requests {
		if request.WorkingDirectory() != workspaceIdentity.SnapshotPath() {
			t.Fatal("FAIL: AGY launch did not use the immutable fixture snapshot")
		}
	}
	capabilityRequest := recordingRunner.requests[1]
	binding, bound := capabilityRequest.ProviderPacketBinding()
	nativeReference := "@" + fixture.Reference()
	if !bound || !binding.Valid() ||
		binding.Channel() != ports.ProviderPacketChannelPromptFile ||
		binding.PromptFileReference() != nativeReference ||
		binding.ArgvIndex() != 12 ||
		binding.SnapshotCWD() != workspaceIdentity.SnapshotPath() {
		t.Fatal("FAIL: AGY capability launch omitted the native prompt-file packet binding")
	}
	if binding.ArgvIndex() >= len(capabilityRequest.Argv()) || capabilityRequest.Argv()[binding.ArgvIndex()] != nativeReference {
		t.Fatal("FAIL: AGY native prompt-file reference is not at the bound argv index")
	}
	capability := recordingRunner.observations[1]
	transportReceipt, transported := capability.ProviderPacketTransportReceipt()
	if !transported || !transportReceipt.Valid() ||
		transportReceipt.Channel() != ports.ProviderPacketChannelPromptFile ||
		transportReceipt.PacketIdentity() != binding.PacketIdentity() ||
		transportReceipt.PromptFileReference() != nativeReference ||
		transportReceipt.SnapshotCWD() != workspaceIdentity.SnapshotPath() {
		t.Fatal("FAIL: AGY capability transport receipt is not bound to the native prompt-file request")
	}
	if liveAgyApprovalPrompt(capability.Stdout()) || liveAgyApprovalPrompt(capability.Stderr()) {
		t.Fatal("FAIL: AGY requested interactive approval")
	}
	liveAgyRequirePostOutputLifecycle(t, capability, binding.PacketIdentity())
	// A terminal JSON frame is optional metadata, not the result transport. When the
	// installed AGY emits one this gate keeps its exact strict-frame contract; when it
	// narrates instead, capability acceptance is decided by the same bound fixture
	// evidence QualifyCurrent already proved above, so the gate stays no stricter than
	// the product it certifies.
	capabilityFrame, frameErr := ports.ExtractProcessOutputJSONFrame(
		ports.ProcessOutputFramingTerminalJSONObject,
		capability.Stdout(),
	)
	if frameErr == nil {
		var evidence struct {
			Root string `json:"root"`
			Link string `json:"link"`
			Role string `json:"role"`
		}
		decoder := json.NewDecoder(bytes.NewReader(capabilityFrame))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&evidence); err != nil {
			t.Fatal("FAIL: AGY capability terminal frame is not strict JSON")
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF ||
			evidence.Root != fixture.Nonce() || evidence.Link != fixture.Link() ||
			evidence.Role != string(fixture.Role()) {
			t.Fatal("FAIL: AGY capability evidence did not contain the exact descriptor-bound positive evidence")
		}
	} else {
		stdout := capability.Stdout()
		if len(bytes.TrimSpace(stdout)) == 0 {
			t.Fatal("FAIL: AGY frameless capability output carried no evidence at all")
		}
		if bytes.Equal(stdout, fixture.Packet()) {
			t.Fatal("FAIL: AGY frameless capability output is a bare prompt echo")
		}
		for _, bound := range []string{fixture.Nonce(), fixture.Link(), string(fixture.Role())} {
			if !bytes.Contains(stdout, []byte(bound)) {
				t.Fatal("FAIL: AGY narrated capability evidence omitted its descriptor-bound values")
			}
		}
		t.Logf("PASS: AGY capability evidence accepted as narrated output bound to the descriptor fixture")
	}
	if !providercli.VersionAtLeast(result.Version, 1, 1, 4) {
		t.Fatal("FAIL: installed AGY version is below required 1.1.4")
	}
	liveAgyRequireExactReceipts(t, result.Receipts)
	authBeforeDrain, err := liveAgyAuthSettingsManifest(runtimeHome)
	if err != nil {
		t.Fatalf("INCONCLUSIVE: capture installed AGY filesystem auth/settings before Mulgae drain: %v", err)
	}

	workspaceReceipt, err := fixture.DrainTerminal(ctx)
	if err != nil || !workspaceReceipt.Valid() || workspaceReceipt.WorkspaceSnapshotIdentity() != workspaceIdentity {
		t.Fatal("FAIL: immutable workspace terminal receipt is invalid")
	}
	runReceipt, err := registry.Close(ctx)
	namespaceReceipts := runReceipt.NamespaceReceipts()
	if err != nil || !runReceipt.Valid() || len(namespaceReceipts) != 1 ||
		!namespaceReceipts[0].Drained() || !namespaceReceipts[0].Unlinked() || !namespaceReceipts[0].TornDown() {
		t.Fatal("FAIL: isolated namespace terminal receipt is invalid")
	}
	// The manifest proves Mulgae setup and teardown never persist changes under the
	// installed HOME. It intentionally does not deny the AGY child its normal
	// user-owned authentication behavior; doing so would recreate the permission
	// failures this native-HOME contract exists to avoid.
	authAfterDrain, snapshotErr := liveAgyAuthSettingsManifest(runtimeHome)
	if snapshotErr != nil {
		t.Fatalf("INCONCLUSIVE: capture installed AGY filesystem auth/settings after drain: %v", snapshotErr)
	}
	if !reflect.DeepEqual(authBeforeDrain, authAfterDrain) {
		t.Fatal("FAIL: Mulgae changed installed AGY filesystem auth/settings surfaces")
	}
	drained = true
	t.Logf("PASS: installed AGY %s completed the descriptor-bound immutable fixture probe", result.Version)
}

func liveAgyRequireExactReceipts(t *testing.T, receipts []providercli.CurrentProbeReceipt) {
	t.Helper()
	want := map[string]struct{}{
		"workspace": {}, "manifest": {}, "namespace": {}, "environment": {},
		"transport": {}, "native-reference": {}, "version": {}, "capability": {},
		"base-role": {}, "assignment": {}, "direct-execution-authority": {},
	}
	if len(receipts) != len(want) {
		t.Fatalf("FAIL: AGY qualification receipt count = %d, want %d", len(receipts), len(want))
	}
	var expiry time.Time
	for _, receipt := range receipts {
		if _, ok := want[receipt.Kind]; !ok {
			t.Fatal("FAIL: AGY qualification receipt kind is missing or duplicated")
		}
		delete(want, receipt.Kind)
		if receipt.ExpiresAt.IsZero() {
			t.Fatal("FAIL: AGY qualification receipt has no expiry")
		}
		if receipt.EvidenceID == "" {
			t.Fatal("FAIL: AGY qualification receipt omitted its evidence binding")
		}
		if receipt.Kind == "direct-execution-authority" {
			if receipt.DirectExecutionAuthority == nil || !receipt.DirectExecutionAuthority.Valid() ||
				!receipt.DirectExecutionAuthority.ExpiresAt().Equal(receipt.ExpiresAt) {
				t.Fatal("FAIL: AGY direct-execution authority receipt is invalid")
			}
		} else if receipt.DirectExecutionAuthority != nil {
			t.Fatal("FAIL: non-authority AGY qualification receipt carried direct-execution authority")
		}
		if expiry.IsZero() {
			expiry = receipt.ExpiresAt
		} else if !receipt.ExpiresAt.Equal(expiry) {
			t.Fatal("FAIL: AGY qualification receipt expiries differ")
		}
	}
	if len(want) != 0 {
		t.Fatal("FAIL: AGY qualification receipt kinds are incomplete")
	}
}

func liveAgyConfiguredPath(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("INCONCLUSIVE: %s is not configured after live opt-in", name)
	}
	if !filepath.IsAbs(value) || filepath.Clean(value) != value {
		t.Fatalf("INCONCLUSIVE: %s is not a canonical absolute path", name)
	}
	return value
}
func liveAgyRequirePostOutputLifecycle(t *testing.T, observation ports.ProcessObservation, expectedPacket ports.ProviderPacketIdentity) {
	t.Helper()
	receipt, ok := observation.LifecycleReceipt()
	if !ok || !receipt.Valid() || !receipt.ProcessGroupAbsent() {
		t.Fatal("FAIL: AGY capability launch omitted a terminal process-group lifecycle receipt")
	}
	frame, framed := receipt.OutputFrame()
	if !framed {
		// Without a frame there is no post-output signal claim to bind: a valid
		// lifecycle receipt can only describe natural completion, and any post-output
		// signal receipt would already have been rejected as unbound.
		if len(receipt.SignalRequests()) != 0 {
			t.Fatal("FAIL: AGY frameless capability launch recorded post-output signal receipts")
		}
		if code, exited := receipt.FinalTermination().ExitCode(); !exited || code != 0 {
			t.Fatal("FAIL: AGY frameless natural completion omitted a successful terminal receipt")
		}
		return
	}
	if !frame.Valid() || frame.Framing() != ports.ProcessOutputFramingTerminalJSONObject {
		t.Fatal("FAIL: AGY capability launch omitted a strict-JSON output-frame receipt")
	}
	requests := receipt.SignalRequests()
	if len(requests) == 0 {
		if code, exited := receipt.FinalTermination().ExitCode(); !exited || code != 0 {
			t.Fatal("FAIL: AGY natural completion omitted a successful terminal receipt")
		}
		return
	}
	if len(requests) > 2 {
		t.Fatalf("FAIL: AGY post-output signal receipt count = %d, want SIGTERM with optional escalation", len(requests))
	}
	first := requests[0]
	packet, packetOK := first.PacketIdentity()
	frameSHA256, frameOK := first.FrameSHA256()
	if !first.Valid() || first.Reason() != ports.ProcessGroupSignalRequestPostOutput ||
		first.Signal().Number() != 15 || first.Signal().Name() != "SIGTERM" ||
		!packetOK || !packet.Valid() || !frameOK || frameSHA256 != frame.SHA256() {
		t.Fatal("FAIL: AGY capability launch omitted the post-output SIGTERM receipt")
	}
	if packet != expectedPacket {
		t.Fatal("FAIL: AGY post-output SIGTERM receipt is not bound to the request packet")
	}
	if len(requests) == 2 {
		escalation := requests[1]
		packet, packetOK := escalation.PacketIdentity()
		frameSHA256, frameOK := escalation.FrameSHA256()
		if !escalation.Valid() || escalation.Reason() != ports.ProcessGroupSignalRequestPostOutputEscalation ||
			escalation.Signal().Number() != 9 || escalation.Signal().Name() != "SIGKILL" ||
			!packetOK || !packet.Valid() || !frameOK || frameSHA256 != frame.SHA256() {
			t.Fatal("FAIL: AGY capability launch recorded an invalid post-output escalation receipt")
		}
		if packet != expectedPacket {
			t.Fatal("FAIL: AGY post-output escalation receipt is not bound to the request packet")
		}
	}
}

func liveAgyTempDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}
func liveAgyEnvironment(t *testing.T, environment []ports.EnvironmentVariable) map[string]string {
	t.Helper()
	values := make(map[string]string, len(environment))
	for _, variable := range environment {
		if _, exists := values[variable.Name()]; exists {
			t.Fatal("duplicate retained AGY namespace environment variable")
		}
		values[variable.Name()] = variable.Value()
	}
	for _, name := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "TMPDIR", "TMP", "TEMP", "MULGAE_PROVIDER_SCRATCH"} {
		if values[name] == "" {
			t.Fatalf("retained AGY namespace omitted %s", name)
		}
	}
	return values
}

func liveAgyOwnedByDisposableNamespace(path, namespaceRoot string) bool {
	relative, err := filepath.Rel(namespaceRoot, path)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

type liveAgyRecordingRunner struct {
	runner       ports.ProcessRunner
	observations []ports.ProcessObservation
	requests     []ports.ProcessRequest
}

func (runner *liveAgyRecordingRunner) Run(ctx context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	runner.requests = append(runner.requests, request)
	observation, err := runner.runner.Run(ctx, request)
	runner.observations = append(runner.observations, observation)
	return observation, err
}

func liveAgyApprovalPrompt(output []byte) bool {
	lower := strings.ToLower(string(output))
	return strings.Contains(lower, "do you approve") || strings.Contains(lower, "approval required") ||
		strings.Contains(lower, "permission required") || strings.Contains(lower, "allow this action")
}
