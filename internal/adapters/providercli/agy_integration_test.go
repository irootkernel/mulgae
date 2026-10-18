//go:build darwin && arm64

package providercli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gittargetadapter "github.com/irootkernel/mulgae/internal/adapters/gittarget"
	processadapter "github.com/irootkernel/mulgae/internal/adapters/process"
	runtimeadapter "github.com/irootkernel/mulgae/internal/adapters/runtime"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

const agyTestTokenPath = ".gemini/antigravity-cli/antigravity-oauth-token"

func agyTestNamespace(t *testing.T) (*namespaceLease, string) {
	t.Helper()
	home := credentialSourceTempDir(t)
	writeCredentialSource(t, home, agyTestTokenPath, "synthetic-auth")
	base, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewCredentialProjectingNamespaceFactory(base, home, map[string]CredentialSourceFamily{"agy-test": CredentialSourceAgy})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "agy-test", FamilyAgy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := lease.DrainTerminal(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return lease.(*namespaceLease), home
}
func TestAgyCredentialAdmissionRejectsUnsafeDefaultAndNeverImportsNativeConfig(t *testing.T) {
	for _, variant := range []string{"missing", "empty", "mode", "symlink", "hardlink", "valid"} {
		t.Run(variant, func(t *testing.T) {
			home := credentialSourceTempDir(t)
			writeCredentialSource(t, home, agyTestTokenPath, "synthetic-auth")
			token := filepath.Join(home, agyTestTokenPath)
			writeCredentialSource(t, home, ".gemini/config/mcp_config.json", "DO_NOT_IMPORT")
			switch variant {
			case "missing":
				if err := os.Remove(token); err != nil {
					t.Fatal(err)
				}
			case "empty":
				if err := os.WriteFile(token, nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(token, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(token, token+"-real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(token+"-real", token); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(token, token+"-link"); err != nil {
					t.Fatal(err)
				}
			}
			base, err := NewNamespaceFactory(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			factory, err := NewCredentialProjectingNamespaceFactory(base, home, map[string]CredentialSourceFamily{"agy-test": CredentialSourceAgy})
			if err != nil {
				t.Fatal(err)
			}
			lease, err := factory.AcquireProviderNamespace(context.Background(), "agy-test", FamilyAgy)
			if variant != "valid" {
				if err == nil {
					_, _ = lease.DrainTerminal(context.Background())
					t.Fatal("unsafe source admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer lease.DrainTerminal(context.Background())
			concrete := lease.(*namespaceLease)
			projected := filepath.Join(concrete.root, "home/.gemini")
			if _, err := os.Lstat(filepath.Join(projected, "config/mcp_config.json")); !os.IsNotExist(err) {
				t.Fatal("imported native MCP configuration")
			}
			if data, err := os.ReadFile(filepath.Join(projected, "antigravity-cli/antigravity-oauth-token")); err != nil || string(data) != "synthetic-auth" {
				t.Fatal("wrong token projection")
			}
			if err := os.WriteFile(filepath.Join(projected, "antigravity-cli/antigravity-oauth-token"), []byte("refreshed-copy"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := concrete.ValidateForSpawn(); err != nil {
				t.Fatal("refreshed disposable token rejected", err)
			}
			if data, err := os.ReadFile(token); err != nil || string(data) != "synthetic-auth" {
				t.Fatal("original token changed")
			}
		})
	}
}

type agyProbeRunner struct {
	t            *testing.T
	fixture      *currentProbeFixture
	requests     []ports.ProcessRequest
	signaled     bool
	drift        bool
	drainUnknown bool
}

type agyFailQualificationObserver struct{}

func (agyFailQualificationObserver) ObserveQualificationProbe(context.Context, ports.QualificationProbeObservation) error {
	return fmt.Errorf("fixture diagnostics persistence failure")
}

func (r *agyProbeRunner) Run(_ context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	r.requests = append(r.requests, request)
	if directory, _, ok := request.LaunchDirectory(); ok {
		_ = directory.Close()
	}
	// Runner.Run returns the plain one-shot observation, without a protocol
	// conversation lifecycle receipt.
	return testProcessObservation(r.t, []byte("1.4.0\n"), nil, ports.ProcessTerminationExited, 0), nil
}
func (r *agyProbeRunner) Converse(ctx context.Context, request ports.ProcessRequest, driver ports.ProviderSessionDriver) (ports.ProcessObservation, error) {
	r.requests = append(r.requests, request)
	if directory, _, ok := request.LaunchDirectory(); ok {
		defer directory.Close()
	}
	agent, gemini := "", ""
	args := request.Argv()
	for i, arg := range args {
		if arg == "--agent" && i+1 < len(args) {
			agent = args[i+1]
		}
		if arg == "--gemini_dir" && i+1 < len(args) {
			gemini = args[i+1]
		}
	}
	ack := agyTestJSON(map[string]any{"event": "init", "conversation_id": "conversation-1", "init": map[string]string{"agent": agent, "permission_mode": "request-review"}})
	proof := fmt.Sprintf(`{"root":%q,"link":%q,"role":%q}`, r.fixture.Nonce(), r.fixture.Link(), r.fixture.Role())
	exchange := &agyTestExchange{frames: [][]byte{ack, agyTestProgress(), agyTestResult(map[string]any{"response": proof})}}
	err := driver.Drive(ctx, exchange)
	if !exchange.closed || len(exchange.sent) != 1 {
		r.t.Fatal("qualification prompt/EOF missing")
	}
	if r.drift {
		if err := os.WriteFile(filepath.Join(gemini, "antigravity-cli/settings.json"), []byte(`{"toolPermission":"yolo"}`), 0600); err != nil {
			r.t.Fatal(err)
		}
	}
	if r.drainUnknown {
		return ports.ProcessObservation{}, fmt.Errorf("fixture process-group drain unverified")
	}
	if r.signaled {
		return protocolTeardownObservation(r.t, []byte("transcript")), err
	}
	return currentProbeCapabilityProtocolObservation(r.t, r.fixture, []byte("transcript")), err
}
func TestAgyCapabilityProofRequiresOneExactJSONObject(t *testing.T) {
	fixture := &currentProbeFixture{role: domain.RoleDocumentation}
	proof := `{"root":"nonce","link":"linked","role":"documentation"}`
	for _, item := range []struct {
		name, output string
		wantOK       bool
	}{
		{"exact", proof, true},
		{"repeated native schema output", strings.Repeat(proof+"\n", 4), false},
		{"narrated", "Readiness confirmed: " + proof, false},
		{"extra field", `{"root":"nonce","link":"linked","role":"documentation","other":true}`, false},
		{"wrong binding", `{"root":"other","link":"linked","role":"documentation"}`, false},
		{"duplicate key", `{"root":"nonce","root":"other","link":"linked","role":"documentation"}`, false},
	} {
		t.Run(item.name, func(t *testing.T) {
			if err := acceptCapabilityEvidence(FamilyAgy, []byte(item.output), fixture); (err == nil) != item.wantOK {
				t.Fatalf("AGY proof acceptance = %v, want accepted=%t", err, item.wantOK)
			}
		})
	}
}

func TestAgyQualificationBindsFinalArgvCodecCredentialsAndNativeBoundary(t *testing.T) {
	for _, variant := range []string{"success", "signaled", "policy drift", "drain unknown", "diagnostics failure"} {
		t.Run(variant, func(t *testing.T) {
			lease, home := agyTestNamespace(t)
			root, identity := testWorkspaceRoot(t)
			fixture := &currentProbeFixture{root: root, identity: identity, role: domain.RoleDocumentation}
			d := currentProbeDefinitionWithExecutionIdentity(testProfile(t, FamilyAgy, "agy-test", "", ""))
			d.runtimeSafetyPolicyIdentity = lease.RuntimeSafetyPolicyIdentity()
			runner := &agyProbeRunner{t: t, fixture: fixture, signaled: variant == "signaled", drift: variant == "policy drift", drainUnknown: variant == "drain unknown"}
			probe, err := NewCurrentProbe(runner, &currentProbeVerifier{})
			if err != nil {
				t.Fatal(err)
			}
			namespace := retainedQualificationNamespace{lease: lease}
			ctx := context.Background()
			if variant == "diagnostics failure" {
				ctx = ports.WithQualificationProbeObserver(ctx, agyFailQualificationObserver{})
			}
			result, err := probe.QualifyCurrent(ctx, CurrentProbeRequest{Definition: d, Namespace: namespace, Fixture: fixture, Invocation: NativeProbeInvocation{}, Now: time.Now().UTC(), TTL: time.Hour})
			if variant != "success" {
				if err == nil {
					t.Fatal("failed qualification accepted")
				}
				if _, err := lease.agyQualifiedCodec(d); err == nil {
					t.Fatal("failed qualification installed codec authority")
				}
				if variant == "drain unknown" {
					agyAssertProfileRetained(t, lease)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.Version != "1.4.0" || len(runner.requests) != 2 {
				t.Fatal("missing version/capability")
			}
			codec, err := lease.agyQualifiedCodec(d)
			if err != nil || codec != "1.4.0" {
				t.Fatal("observed codec was not bound", err)
			}
			mutated := d
			mutated.agyModel = "other-model"
			mutated.agySettingsIdentity = agySettingsIdentity(mutated.agyModel, "")
			if _, err := lease.agyQualifiedCodec(mutated); err == nil {
				t.Fatal("changed runtime reused qualification")
			}
			request := runner.requests[1]
			boundary, ok := request.LiveReadOnlyBoundary()
			if !ok || !boundary.OwnedPTY() || !anchoredContains(boundary.CredentialRoots(), filepath.Join(home, ".gemini")) || request.WorkingDirectory() != filepath.Join(lease.root, "scratch") {
				t.Fatal("missing native guard/neutral cwd/original home denial")
			}
			env := credentialSourceEnvironment(request.Environment())
			if env["SSH_TTY"] != "/dev/null" || env["HOME"] != filepath.Join(lease.root, "home") {
				t.Fatal("wrong auth environment")
			}
			if strings.Contains(strings.Join(request.Argv(), " "), "--json-schema") {
				t.Fatal("qualification must validate prompt-bound JSON without native schema retries")
			}
			encoded, _ := json.Marshal(request.Argv())
			sum := sha256.Sum256(encoded)
			want := "sha256:" + hex.EncodeToString(sum[:])
			found := false
			for _, receipt := range result.Receipts {
				if receipt.DirectExecutionAuthority != nil {
					for _, proof := range receipt.DirectExecutionAuthority.proofs {
						if proof.ArgvSHA256 != want || proof.AgyCredentialSourceIdentity == "" {
							t.Fatal("proof does not bind final argv/source")
						}
						found = true
					}
				}
			}
			if !found {
				t.Fatal("no direct proof")
			}
			gemini, _ := lease.agyProjectedGeminiHome()
			if _, err := os.Lstat(filepath.Join(gemini, "antigravity-cli/settings.json")); !os.IsNotExist(err) {
				t.Fatal("invocation settings leaked across turns")
			}
			sourceBefore, err := namespace.agyCredentialIdentity()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(home, agyTestTokenPath), []byte("changed-original"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := namespace.agyCredentialIdentity(); err == nil {
				t.Fatal("changed source kept credential authority", sourceBefore)
			}
		})
	}
}
func TestAgyVersionFloorAndEnvironmentHaveNoImplicitAccountOverride(t *testing.T) {
	for _, test := range []struct {
		version string
		ok      bool
	}{{"1.2.8", false}, {"1.2.9-beta", false}, {"1.2.9", true}, {"1.4.0", true}} {
		observation := testProcessObservation(t, []byte(test.version), nil, ports.ProcessTerminationExited, 0)
		_, err := plainSemver(FamilyAgy, observation)
		if (err == nil) != test.ok {
			t.Fatal(test.version, err)
		}
	}
	lease, _ := agyTestNamespace(t)
	override, _ := ports.NewEnvironmentVariable("GEMINI_API_KEY", "must-not-flow")
	ssh, _ := ports.NewEnvironmentVariable("SSH_TTY", "other")
	env, err := isolatedProcessEnvironment(FamilyAgy, []ports.EnvironmentVariable{override, ssh}, lease.Environment())
	if err != nil {
		t.Fatal(err)
	}
	values := credentialSourceEnvironment(env)
	if values["SSH_TTY"] != "/dev/null" || values["GEMINI_API_KEY"] != "" {
		t.Fatal("implicit account override")
	}
}

type agyLiveTestRunner struct {
	*agyProbeRunner
	path       string
	rejectPath bool
	extraction bool
}

func (r *agyLiveTestRunner) Converse(ctx context.Context, request ports.ProcessRequest, driver ports.ProviderSessionDriver) (ports.ProcessObservation, error) {
	r.requests = append(r.requests, request)
	if directory, _, ok := request.LaunchDirectory(); ok {
		defer directory.Close()
	}
	agent, gemini := "", ""
	args := request.Argv()
	for i, arg := range args {
		if arg == "--agent" && i+1 < len(args) {
			agent = args[i+1]
		}
		if arg == "--gemini_dir" && i+1 < len(args) {
			gemini = args[i+1]
		}
	}
	frames := [][]byte{agyTestJSON(map[string]any{"event": "init", "conversation_id": "conversation-1", "init": map[string]string{"agent": agent, "permission_mode": "request-review"}})}
	if !r.extraction {
		path := r.path
		if r.rejectPath {
			path = filepath.Join(gemini, "antigravity-cli/antigravity-oauth-token")
		}
		for _, state := range []string{"ACTIVE", "DONE"} {
			frames = append(frames, agyTestStep(map[string]any{"conversation_id": "conversation-1", "step_index": 2, "step_type": "tool", "state": state, "tool_name": "view_file", "tool_info": map[string]any{"name": "view_file", "parameters": map[string]string{"AbsolutePath": path}, "output": "fixture read"}}))
		}
	}
	frames = append(frames, agyTestProgress(), agyTestResult(nil))
	exchange := &agyTestExchange{frames: frames}
	err := driver.Drive(ctx, exchange)
	if r.drift {
		if err := os.WriteFile(filepath.Join(gemini, "antigravity-cli/settings.json"), []byte(`{"toolPermission":"yolo"}`), 0600); err != nil {
			r.t.Fatal(err)
		}
	}
	if r.drainUnknown {
		return ports.ProcessObservation{}, fmt.Errorf("fixture process-group drain unverified")
	}
	if r.signaled {
		return protocolTeardownObservation(r.t, []byte("transcript")), err
	}
	return currentProbeCapabilityProtocolObservation(r.t, r.fixture, []byte("transcript")), err
}
func TestAgyLiveReviewAndExtractionUseExactPlanAndRejectFailedCandidate(t *testing.T) {
	for _, variant := range []string{"review", "extraction", "Git authority", "credential path", "policy drift", "signals", "drain unknown"} {
		t.Run(variant, func(t *testing.T) {
			ctx := context.Background()
			lease, operator := agyTestNamespace(t)
			base := credentialSourceTempDir(t)
			project := filepath.Join(base, "project")
			if err := os.Mkdir(project, 0700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(project, "target.txt")
			if variant == "Git authority" {
				target = filepath.Join(project, "target's file.txt")
			}
			if err := os.WriteFile(target, []byte("original source\n"), 0600); err != nil {
				t.Fatal(err)
			}
			git := func(args ...string) {
				t.Helper()
				command := exec.Command("/usr/bin/git", append([]string{"-C", project}, args...)...)
				command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/var/empty", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"}
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatalf("git: %v %s", err, output)
				}
			}
			git("init", "--quiet")
			git("add", filepath.Base(target))
			git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Baseline")
			if variant == "Git authority" {
				if err := os.WriteFile(target, []byte("index source\n"), 0600); err != nil {
					t.Fatal(err)
				}
				git("add", filepath.Base(target))
			}
			operatorRoot, _ := ports.NewAnchoredRoot(operator)
			home, err := OpenReviewerHome(operatorRoot, []byte("trusted guide"))
			if err != nil {
				t.Fatal(err)
			}
			defer home.Close()
			credential, _ := ports.NewAnchoredRoot(filepath.Join(operator, ".gemini"))
			adapter, err := gittargetadapter.NewLiveSourceAdapter(gittargetadapter.NewExecRunner(), []ports.AnchoredRoot{credential})
			if err != nil {
				t.Fatal(err)
			}
			projectRoot, _ := ports.NewAnchoredRoot(project)
			selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
			if variant == "Git authority" {
				selector, _ = ports.NewLiveSourceSelector(domain.LiveSourceStage, "")
			}
			source, err := adapter.OpenLiveSource(ctx, projectRoot, selector)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			execution, err := ports.NewLiveReviewExecution(ctx, source, home, []ports.AnchoredRoot{credential})
			if err != nil {
				t.Fatal(err)
			}
			if variant == "Git authority" {
				plan, err := agyLiveReadPlan(ctx, execution, false)
				if err != nil {
					t.Fatal(err)
				}
				authority, err := newAgyLiveReadAuthority(ctx, execution)
				if err != nil {
					t.Fatal(err)
				}
				if len(plan.commands) == 0 || len(plan.commands) != len(execution.Reads()) {
					t.Fatal("missing Git authority")
				}
				for i, read := range execution.Reads() {
					command := "MULGAE_READ_GUARD[1]=1 " + read.GitCommand()
					if plan.commands[i] != command || authority.allow(ctx, "run_command", command) != nil {
						t.Fatal("policy and driver differ from the AGY guarded read plan")
					}
					for _, rejected := range []string{read.GitCommand(), command + " 'HEAD:other.txt'", command + "; " + command, strings.Replace(command, " show ", "  show ", 1), strings.ReplaceAll(command, "'", "\""), "1 1 " + read.GitCommand()} {
						if authority.allow(ctx, "run_command", rejected) == nil {
							t.Fatal("modified command gained driver authority")
						}
					}
				}
				return
			}
			d := testProfile(t, FamilyAgy, "agy-test", "", "sha256:test")
			d.runtimeSafetyPolicyIdentity = lease.RuntimeSafetyPolicyIdentity()
			if err := (retainedQualificationNamespace{lease: lease}).recordAgyQualification(d, "1.4.0"); err != nil {
				t.Fatal(err)
			}
			root, identity := testWorkspaceRoot(t)
			fixture := &currentProbeFixture{root: root, identity: identity}
			runner := &agyLiveTestRunner{agyProbeRunner: &agyProbeRunner{t: t, fixture: fixture, drift: variant == "policy drift", signaled: variant == "signals", drainUnknown: variant == "drain unknown"}, path: target, rejectPath: variant == "credential path", extraction: variant == "extraction"}
			registry := &Registry{runner: runner}
			purpose := ports.ProviderInvocationInitial
			if runner.extraction {
				purpose = ports.ProviderInvocationExtract
			}
			initial := testInvocation(t, "agy-test")
			invocation, err := ports.NewProviderInvocation(initial.Role(), "agy-test", initial.AttemptID(), purpose, []byte("fixture"), "i_019f596a-cf80-7c67-b265-f37053d51ccd", "019f596a-cf80-7c67-b265-f37053d51cce", testStdinDigest([]byte("fixture")))
			if err != nil {
				t.Fatal(err)
			}
			observation, report, err := registry.runInLiveSource(ctx, definition(d), invocation, execution, invocation.Packet(), lease)
			if variant != "review" && variant != "extraction" {
				if err == nil || len(report) != 0 {
					t.Fatal("failed live candidate returned report", err, string(report))
				}
				if variant == "drain unknown" {
					agyAssertProfileRetained(t, lease)
				}
				return
			}
			if err != nil || !agyNaturalExitObservation(observation) || string(report) != "actual final report" {
				t.Fatal("live route", err, string(report))
			}
			request := runner.requests[0]
			boundary, guarded := request.LiveReadOnlyBoundary()
			if !guarded || !boundary.OwnedPTY() || request.WorkingDirectory() != home.Root().String() || !anchoredContains(boundary.CredentialRoots(), credential.String()) {
				t.Fatal("live route lost guard/cwd/credentials")
			}
			if data, err := os.ReadFile(target); err != nil || string(data) != "original source\n" {
				t.Fatal("source modified")
			}
		})
	}
}

func agyAssertProfileRetained(t *testing.T, lease *namespaceLease) {
	t.Helper()
	if err := lease.ValidateForSpawn(); err == nil {
		t.Fatal("unverified provider drain allowed namespace reuse")
	}
	if _, err := lease.DrainTerminal(context.Background()); err == nil {
		t.Fatal("unverified provider drain allowed namespace removal")
	}
	// These scripted runners launched no process. Release their simulated
	// failure after asserting retention, so fixture cleanup can finish.
	t.Cleanup(func() {
		lease.terminalMu.Lock()
		lease.agyDrainUnverified = false
		lease.terminalMu.Unlock()
	})
	gemini, err := lease.agyProjectedGeminiHome()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"antigravity-cli/settings.json", "config/mcp_config.json"} {
		if _, err := os.Stat(filepath.Join(gemini, name)); err != nil {
			t.Fatal("profile removed before verified process drain", name, err)
		}
	}
	agents, err := os.ReadDir(filepath.Join(gemini, "config/agents"))
	if err != nil || len(agents) != 1 {
		t.Fatal("controlled agent removed before verified process drain", err)
	}
}

func TestAgyCredentialFIFOAdmissionDoesNotWaitForAWriter(t *testing.T) {
	home := credentialSourceTempDir(t)
	writeCredentialSource(t, home, agyTestTokenPath, "synthetic-auth")
	token := filepath.Join(home, agyTestTokenPath)
	if err := os.Remove(token); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(token, 0600); err != nil {
		t.Fatal(err)
	}
	base, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewCredentialProjectingNamespaceFactory(base, home, map[string]CredentialSourceFamily{"agy-test": CredentialSourceAgy})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		lease, err := factory.AcquireProviderNamespace(context.Background(), "agy-test", FamilyAgy)
		if lease != nil {
			_, _ = lease.DrainTerminal(context.Background())
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO admitted as a credential")
		}
	case <-time.After(time.Second):
		// Release the blocked open before failing so the regression never
		// leaves a goroutine or modifying acquisition behind.
		fd, err := unix.Open(token, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		<-done
		_ = unix.Close(fd)
		t.Fatal("credential admission blocked waiting for a FIFO writer")
	}
}

func TestAgyCredentialRevalidationRejectsNewSourceHardlinks(t *testing.T) {
	lease, home := agyTestNamespace(t)
	if err := os.Link(filepath.Join(home, agyTestTokenPath), filepath.Join(home, "token-alias")); err != nil {
		t.Fatal(err)
	}
	if err := lease.ValidateForSpawn(); err == nil {
		t.Fatal("changed source link count retained credential authority")
	}
}

func TestAgyQualificationKernelBoundarySeparatesNeutralCwdAndNativeHome(t *testing.T) {
	lease, operator := agyTestNamespace(t)
	fixture := credentialSourceTempDir(t)
	source := filepath.Join(fixture, "source.txt")
	if err := os.WriteFile(source, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(fixture)
	if err != nil {
		t.Fatal(err)
	}
	boundary, neutral, err := (retainedQualificationNamespace{lease: lease}).agyQualificationBinding(root)
	if err != nil {
		t.Fatal(err)
	}
	gemini, err := lease.agyProjectedGeminiHome()
	if err != nil {
		t.Fatal(err)
	}
	projected := filepath.Join(gemini, "antigravity-cli/antigravity-oauth-token")
	script := `set -eu
printf refreshed-copy > "$1"
if (printf changed > "$2") 2>/dev/null; then exit 41; fi
if (printf changed > "$3") 2>/dev/null; then exit 42; fi
if /bin/cat "$4" >/dev/null 2>&1; then exit 43; fi
printf boundary-ok`
	packet, _ := ports.NewProviderPacketFromBytes([]byte("AGY kernel fixture"))
	binding, _ := ports.NewProtocolProviderPacketBinding(packet)
	environment, err := isolatedProcessEnvironment(FamilyAgy, nil, lease.Environment())
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewProviderProtocolProcessRequest("/bin/sh", []string{"/bin/sh", "-c", script, "fixture", projected, source, filepath.Join(neutral.String(), "forbidden.txt"), filepath.Join(operator, agyTestTokenPath)}, environment, neutral.String(), binding, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request, err = ports.NewLiveReadOnlyProcessRequest(request, boundary)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(neutral.String())
	if err != nil {
		t.Fatal(err)
	}
	request, err = ports.NewNeutralBoundProcessRequest(request, neutral, directory)
	if err != nil {
		_ = directory.Close()
		t.Fatal(err)
	}
	runner, err := processadapter.NewRunner(runtimeadapter.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	observation, err := runner.Run(context.Background(), request)
	if err != nil || !observation.Succeeded() || string(observation.Stdout()) != "boundary-ok" {
		code, hasCode := observation.ExitCode()
		lifecycle, hasLifecycle := observation.LifecycleReceipt()
		t.Fatalf("kernel boundary: %v; termination=%s exit=%d/%t lifecycle=%t absent=%t stdout=%q stderr=%s", err, observation.Termination(), code, hasCode, hasLifecycle, lifecycle.ProcessGroupAbsent(), observation.Stdout(), observation.Stderr())
	}
	for path, want := range map[string]string{source: "original", projected: "refreshed-copy", filepath.Join(operator, agyTestTokenPath): "synthetic-auth"} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != want {
			t.Fatal("kernel boundary file integrity", path, err)
		}
	}
}
