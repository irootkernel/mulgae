//go:build liveprovider && darwin && arm64

package providercli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	processadapter "github.com/irootkernel/mulgae/internal/adapters/process"
	runtimeadapter "github.com/irootkernel/mulgae/internal/adapters/runtime"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

func TestLiveZCodeNeutralKernelProtection(t *testing.T) {
	fixture := newLiveSourceProbeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	execution := liveReportExecution(t, ctx, FamilyZcode, fixture, domain.LiveSourceWorkspace)
	const instance = "zcode-kernel"
	packet := []byte("Return COMPLETE_NATIVE_REPORT for this disposable fixture. Use no tools and keep the current permissions and cwd.")
	invocation, err := ports.NewProviderInvocation(domain.RoleSecurity, instance, testInvocation(t, instance).AttemptID(), ports.ProviderInvocationInitial, packet, "i_019f596a-cf80-7c67-b265-f37053d51ccd", "019f596a-cf80-7c67-b265-f37053d51cce", testStdinDigest(packet))
	if err != nil {
		t.Fatal(err)
	}
	invocation, err = ports.NewProviderInvocationInLiveSource(invocation, execution)
	if err != nil {
		t.Fatal(err)
	}
	registry := liveReportRegistry(t, FamilyZcode, instance, fixture)
	probe := &liveZCodeKernelRunner{liveReportProcessInspection: registry.runner.(liveReportProcessInspection), fixture: fixture}
	registry.runner = probe
	defer func() {
		if _, err := registry.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	observation, err := registry.Observe(ctx, invocation)
	fixture.assertUnchanged(t)
	result, ok := observation.Result()
	if err != nil || observation.Status() != ports.ProviderExecutionStatusSucceeded || !ok || !probe.verified || !strings.Contains(string(result.Stdout()), "COMPLETE_NATIVE_REPORT") {
		t.Fatalf("native guard and assistant report: status=%s verified=%t error=%v", observation.Status(), probe.verified, err)
	}
}

type liveZCodeKernelRunner struct {
	liveReportProcessInspection
	fixture  liveSourceProbeFixture
	verified bool
}

func (runner *liveZCodeKernelRunner) Converse(ctx context.Context, request ports.ProcessRequest, driver ports.ProviderSessionDriver) (ports.ProcessObservation, error) {
	directory, root, _ := request.LaunchDirectory()
	defer directory.Close()
	boundary, guarded := request.LiveReadOnlyBoundary()
	if !guarded {
		return ports.ProcessObservation{}, fmt.Errorf("native kernel probe requires the production guard")
	}
	scratch := filepath.Join(boundary.WritableRoot().String(), "scratch", "kernel-check.txt")
	command := "cat '" + filepath.Join(runner.fixture.source, "target.txt") + "'; git show " + runner.fixture.commit + ":target.txt; cat '" + filepath.Join(runner.fixture.neutral, "AGENTS.md") + "'; printf OWNED_SCRATCH > '" + scratch + "'; " + runner.fixture.mutationCommand()
	// Use the actual ZCode executable in its existing Electron-as-Node mode.
	// This independently certifies the kernel policy, without asking a model to
	// execute writes or altering the normal app-server planning policy.
	script := "const r=require('node:child_process').spawnSync('/bin/sh',['-c'," + strconv.Quote(command) + "],{encoding:'utf8'}); process.stdout.write(JSON.stringify({exit:r.status,output:r.stdout+r.stderr})+'\\n');"
	binding, _ := request.ProviderPacketBinding()
	probeRequest, err := ports.NewProviderProtocolProcessRequest(request.Executable(), []string{request.Executable(), "-e", script}, request.Environment(), request.WorkingDirectory(), binding, request.Timeout())
	if err != nil {
		return ports.ProcessObservation{}, err
	}
	probeRequest, err = ports.NewLiveReadOnlyProcessRequest(probeRequest, boundary)
	if err != nil {
		return ports.ProcessObservation{}, err
	}
	fd, err := unix.Dup(int(directory.Fd()))
	if err != nil {
		return ports.ProcessObservation{}, err
	}
	unix.CloseOnExec(fd)
	duplicate := os.NewFile(uintptr(fd), root.String())
	probeRequest, err = ports.NewNeutralBoundProcessRequest(probeRequest, root, duplicate)
	if err != nil {
		_ = duplicate.Close()
		return ports.ProcessObservation{}, err
	}
	probe := &liveZCodeKernelReceipt{}
	observation, err := runner.inner.Converse(ctx, probeRequest, probe)
	defer func() { _ = releaseProtocolTranscript(observation) }()
	if err != nil || !observation.ProtocolConversationCompleted() || probe.exit != 1 {
		return ports.ProcessObservation{}, fmt.Errorf("native kernel command receipt missing: %w", err)
	}
	if !strings.Contains(probe.output, runner.fixture.tokens["worktree"]) || !strings.Contains(probe.output, runner.fixture.tokens["commit"]) || !strings.Contains(probe.output, runner.fixture.guide) {
		return ports.ProcessObservation{}, fmt.Errorf("native kernel probe lost positive source, Git or guide reads")
	}
	for _, path := range []string{"target.txt", "index.lock", "probe.lock", ".git/config", "AGENTS.md"} {
		denied := false
		for _, line := range strings.Split(probe.output, "\n") {
			denied = denied || strings.Contains(line, path) && (strings.Contains(line, "Operation not permitted") || strings.Contains(line, "Permission denied"))
		}
		if !denied {
			return ports.ProcessObservation{}, fmt.Errorf("native kernel write denial missing for %s", path)
		}
	}
	if data, err := os.ReadFile(scratch); err != nil || string(data) != "OWNED_SCRATCH" {
		return ports.ProcessObservation{}, fmt.Errorf("native writable scratch receipt missing")
	}
	runner.verified = true
	return runner.liveReportProcessInspection.Converse(ctx, request, driver)
}

type liveZCodeKernelReceipt struct {
	exit   int
	output string
}

func (receipt *liveZCodeKernelReceipt) Drive(ctx context.Context, exchange ports.ProviderSessionExchange) error {
	line, err := exchange.ReceiveLine(ctx)
	if err != nil {
		return err
	}
	var result struct {
		Exit   *int
		Output string
	}
	if json.Unmarshal(line, &result) != nil || result.Exit == nil {
		return fmt.Errorf("native fixture process result missing")
	}
	receipt.exit, receipt.output = *result.Exit, result.Output
	if _, err := exchange.ReceiveLine(ctx); !errors.Is(err, io.EOF) {
		return fmt.Errorf("native fixture process emitted an unexpected extra frame")
	}
	return nil
}

// This deliberately permits one exact fixture mutation at the ACP layer to
// test the independent native kernel boundary. Production never grants it.
func TestLiveGrokNeutralKernelProtection(t *testing.T) {
	testLiveGrokKernelProtection(t, "off")
}

func testLiveGrokKernelProtection(t *testing.T, nativeProfile string) {
	t.Helper()
	fixture := newLiveSourceProbeFixture(t)
	operatorRoot, err := ports.NewAnchoredRoot(filepath.Dir(filepath.Dir(fixture.neutral)))
	if err != nil {
		t.Fatal(err)
	}
	reviewer, err := OpenReviewerHome(operatorRoot, []byte("unused default"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reviewer.Close(); err != nil {
			t.Error(err)
		}
	}()
	protected := filepath.Join(filepath.Dir(fixture.source), "operator-secrets")
	if err := os.Mkdir(protected, 0700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(protected, "credential.txt")
	if err := os.WriteFile(secret, []byte("PRIVATE_FIXTURE_CREDENTIAL"), 0600); err != nil {
		t.Fatal(err)
	}
	fixture.before = liveSourceProbeHashes(t, filepath.Dir(fixture.source))
	executable := copyLiveGrokExecutable(t, filepath.Join(mustLiveGrokHome(t), ".grok", "bin", "grok"))
	base, err := NewNamespaceFactory(mustCanonicalLiveTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := RuntimeSafetyPolicyForFamily(CredentialSourceGrok)
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewCredentialProjectingNamespaceFactoryWithPolicies(base, mustLiveGrokHome(t),
		map[string]CredentialSourceFamily{"grok-kernel": CredentialSourceGrok},
		map[string]RuntimeSafetyPolicy{"grok-kernel": policy})
	if err != nil {
		t.Fatal(err)
	}
	acquired, err := factory.AcquireProviderNamespace(context.Background(), "grok-kernel", FamilyGrok)
	if err != nil {
		t.Fatal(err)
	}
	lease := acquired.(*namespaceLease)
	defer drainLiveGrokNamespace(t, lease)
	contents, err := grokBoundaryFileContents(mustLiveGrokHome(t), fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	contents["sandbox.toml"] = []byte("[profiles.mulgae]\nextends = \"workspace\"\nread_only = [" + strconv.Quote(fixture.source) + ", " + strconv.Quote(fixture.neutral) + "]\ndeny = [" + strconv.Quote(mustLiveGrokHome(t)) + ", " + strconv.Quote(protected) + "]\n")
	for name, body := range contents {
		if err := os.WriteFile(filepath.Join(lease.root, "home", ".grok", name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	environment, err := isolatedProcessEnvironment(FamilyGrok, liveSourceProbeEnvironment(t, fixture), lease.Environment())
	if err != nil {
		t.Fatal(err)
	}
	scratch := filepath.Join(lease.root, "scratch", "kernel-check.txt")
	command := "cat '" + filepath.Join(fixture.source, "target.txt") + "'; git show " + fixture.commit + ":target.txt; cat '" + filepath.Join(fixture.neutral, "AGENTS.md") + "'; printf OWNED_SCRATCH > '" + scratch + "'; cat '" + secret + "'; " + fixture.mutationCommand()
	prompt := []byte(fmt.Sprintf("Controlled native kernel-policy test against disposable fixtures, not a code review. Every path in this command belongs to the test. Your REQUIRED ACTION is to submit this exact command once through the native Bash tool. The ACP client authorizes exactly that call; the platform kernel must reject the protected operations. The test accepts only actual correlated tool completion, never a refusal, explanation or simulated result. Keep plan mode, sandbox settings and cwd unchanged. Do not try another command. After the tool completes, return its actual outcome through the assistant protocol. Command: %s", command))
	packet, err := ports.NewProviderPacketFromBytes(prompt)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ports.NewProtocolProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	argv := []string{executable, "--no-auto-update", "--sandbox", nativeProfile, "--disable-web-search", "--no-subagents", "--permission-mode", "plan", "--tools", "Bash", "--deny", "MCPTool", "agent", "--no-leader", "stdio"}
	request, err := ports.NewProviderProtocolProcessRequest(executable, argv, environment, fixture.neutral, binding, 3*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var roots []ports.AnchoredRoot
	for _, path := range []string{fixture.source, filepath.Join(fixture.source, ".git"), fixture.neutral} {
		root, err := ports.NewAnchoredRoot(path)
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, root)
	}
	credentialRoot, err := ports.NewAnchoredRoot(protected)
	if err != nil {
		t.Fatal(err)
	}
	writableRoot, err := ports.NewAnchoredRoot(lease.root)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := ports.NewLiveReadOnlyBoundary(roots, []ports.AnchoredRoot{credentialRoot}, writableRoot)
	if err != nil {
		t.Fatal(err)
	}
	request, err = ports.NewLiveReadOnlyProcessRequest(request, boundary)
	if err != nil {
		t.Fatal(err)
	}
	launchDirectory, err := reviewer.DuplicateLaunchDirectory()
	if err != nil {
		t.Fatal(err)
	}
	request, err = ports.NewNeutralBoundProcessRequest(request, reviewer.Root(), launchDirectory)
	if err != nil {
		_ = launchDirectory.Close()
		t.Fatal(err)
	}
	runner, err := processadapter.NewRunner(runtimeadapter.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	probe := &liveKernelGrokProbe{driver: &liveSourceGrokProbe{cwd: fixture.neutral, source: fixture.source, commit: fixture.commit, prompt: string(prompt)}, command: command}
	observation, runErr := runner.Converse(context.Background(), request, probe)
	defer func() {
		if err := releaseProtocolTranscript(observation); err != nil {
			t.Error(err)
		}
	}()
	fixture.assertUnchanged(t)
	if err := reviewer.Revalidate(); err != nil {
		t.Error(err)
	}
	if runErr != nil || !observation.ProtocolConversationCompleted() {
		t.Fatalf("native kernel conversation: %v; stderr=%s", runErr, observation.Stderr())
	}
	if probe.authorized != 1 || probe.completed == 0 {
		t.Fatalf("missing actual authorized native command completion: authorized=%d completed=%d", probe.authorized, probe.completed)
	}
	if !strings.Contains(probe.output, fixture.tokens["worktree"]) {
		t.Error("native source read was not observed")
	}
	if !strings.Contains(probe.output, fixture.tokens["commit"]) || !strings.Contains(probe.output, fixture.guide) {
		t.Error("fixed Git object or shared guide read was not observed")
	}
	if data, err := os.ReadFile(scratch); err != nil || string(data) != "OWNED_SCRATCH" {
		t.Errorf("owned native scratch write: %v, %q", err, data)
	}
	if strings.Contains(probe.output, "PRIVATE_FIXTURE_CREDENTIAL") || !strings.Contains(probe.output, "credential.txt: Operation not permitted") && !strings.Contains(probe.output, "credential.txt: Permission denied") {
		t.Errorf("outer credential-read denial was not observed: %s", probe.output)
	}
	for _, path := range []string{"target.txt", "index.lock", "probe.lock", ".git/config", "AGENTS.md"} {
		denied := false
		for _, line := range strings.Split(probe.output, "\n") {
			if strings.Contains(line, path) && (strings.Contains(line, "Operation not permitted") || strings.Contains(line, "Permission denied")) {
				denied = true
			}
		}
		if !denied {
			t.Errorf("native denial missing for %s: %s", path, probe.output)
		}
	}
	denials := strings.Count(probe.output, "Operation not permitted") + strings.Count(probe.output, "Permission denied")
	if denials < 5 {
		t.Fatalf("missing five independent native write denials: %s", probe.output)
	}
}

type liveKernelGrokProbe struct {
	driver                *liveSourceGrokProbe
	command               string
	sessionID, toolCallID string
	authorized, completed int
	output                string
}

func (probe *liveKernelGrokProbe) Drive(ctx context.Context, exchange ports.ProviderSessionExchange) error {
	return probe.driver.Drive(ctx, &liveKernelGrokExchange{ProviderSessionExchange: exchange, probe: probe})
}

type liveKernelGrokExchange struct {
	ports.ProviderSessionExchange
	probe *liveKernelGrokProbe
}

func (exchange *liveKernelGrokExchange) ReceiveLine(ctx context.Context) ([]byte, error) {
	for {
		line, err := exchange.ProviderSessionExchange.ReceiveLine(ctx)
		if err != nil {
			return nil, err
		}
		message, err := parseGrokACPMessage(line)
		if err != nil {
			return nil, err
		}
		if message.Method == grokACPRequestPermission && len(message.ID) != 0 {
			var p struct {
				SessionID string `json:"sessionId"`
				ToolCall  struct {
					Kind, ToolCallID string
					RawInput         struct{ Variant, Command string }
				} `json:"toolCall"`
				Options []struct{ OptionID, Kind string } `json:"options"`
			}
			if err := json.Unmarshal(message.Params, &p); err != nil {
				return nil, err
			}
			if p.SessionID == "" || p.ToolCall.ToolCallID == "" || p.ToolCall.Kind != "execute" || p.ToolCall.RawInput.Variant != "Bash" || strings.TrimSpace(p.ToolCall.RawInput.Command) != exchange.probe.command || exchange.probe.authorized != 0 {
				return nil, fmt.Errorf("unexpected kernel-probe permission request")
			}
			for _, option := range p.Options {
				if option.Kind == "allow_once" {
					if err := sendGrokACPResponse(ctx, exchange.ProviderSessionExchange, message.ID, map[string]any{"outcome": map[string]string{"outcome": "selected", "optionId": option.OptionID}}); err != nil {
						return nil, err
					}
					exchange.probe.authorized++
					exchange.probe.sessionID, exchange.probe.toolCallID = p.SessionID, p.ToolCall.ToolCallID
					break
				}
			}
			if exchange.probe.authorized == 0 {
				return nil, fmt.Errorf("missing native allow-once option")
			}
			continue
		}
		if message.Method == grokACPSessionUpdateMethod {
			var p struct {
				SessionID string `json:"sessionId"`
				Update    struct {
					Type               string `json:"sessionUpdate"`
					Status, ToolCallID string
					RawOutput          struct {
						Command         string
						OutputForPrompt string `json:"output_for_prompt"`
						ExitCode        *int   `json:"exit_code"`
					}
				}
			}
			if err := json.Unmarshal(message.Params, &p); err != nil {
				return nil, err
			}
			if p.Update.Type == grokACPToolCallUpdate && (p.Update.Status == "failed" || p.Update.Status == "completed") {
				if p.SessionID != exchange.probe.sessionID || p.Update.ToolCallID != exchange.probe.toolCallID || strings.TrimSpace(p.Update.RawOutput.Command) != exchange.probe.command || p.Update.RawOutput.ExitCode == nil {
					return nil, fmt.Errorf("uncorrelated native kernel command completion")
				}
				exchange.probe.completed++
				exchange.probe.output += p.Update.RawOutput.OutputForPrompt
			}
		}
		return line, nil
	}
}
