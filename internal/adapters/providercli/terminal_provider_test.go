//go:build darwin && arm64

package providercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// fakeTerminalSessionRunner records TerminalExecutionRequests and executes a
// scripted handler simulating herdr-core + pane execution strictly offline.
type fakeTerminalSessionRunner struct {
	identity       ports.TerminalRuntimeIdentity
	identityErr    error
	runFunc        func(ctx context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error)
	drainCalls     [][2]string
	drainErr       error
	closeCalls     int
	closeErr       error
	requests       []ports.TerminalExecutionRequest
	runtimeIDCalls int
}

func defaultFakeTerminalIdentity(t *testing.T) ports.TerminalRuntimeIdentity {
	t.Helper()
	id, err := ports.NewTerminalRuntimeIdentity(
		"/opt/homebrew/bin/herdr-core",
		"sha256:"+strings.Repeat("a", 64),
		"0.1.0",
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *fakeTerminalSessionRunner) RunTerminal(ctx context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
	f.requests = append(f.requests, req)
	if dir, _, ok := req.Process().LaunchDirectory(); ok && dir != nil {
		defer func() { _ = dir.Close() }()
	}
	if f.runFunc != nil {
		return f.runFunc(ctx, req)
	}
	return ports.TerminalExecutionObservation{}, errors.New("fakeTerminalSessionRunner: unexpected RunTerminal")
}

func (f *fakeTerminalSessionRunner) DrainLabeledPanes(_ context.Context, key, value string) error {
	f.drainCalls = append(f.drainCalls, [2]string{key, value})
	return f.drainErr
}

func (f *fakeTerminalSessionRunner) RuntimeIdentity(_ context.Context) (ports.TerminalRuntimeIdentity, error) {
	f.runtimeIDCalls++
	if f.identityErr != nil {
		return ports.TerminalRuntimeIdentity{}, f.identityErr
	}
	return f.identity, nil
}

func (f *fakeTerminalSessionRunner) Close(_ context.Context) error {
	f.closeCalls++
	return f.closeErr
}

func makeTerminalProcessObservation(
	t *testing.T,
	req ports.TerminalExecutionRequest,
	termination ports.ProcessTermination,
	exitCode int,
	pgAbsent bool,
	stdout, stderr []byte,
) ports.ProcessObservation {
	t.Helper()
	binding, ok := req.Process().ProviderPacketBinding()
	if !ok {
		t.Fatal("missing provider packet binding on terminal request")
	}
	packet := binding.Packet()
	promptBytes, err := os.ReadFile(req.PromptFilePath().String())
	if err != nil {
		t.Fatalf("read staged prompt file %s: %v", req.PromptFilePath().String(), err)
	}
	promptSum := sha256.Sum256(promptBytes)
	promptIdentity, err := ports.NewProviderPacketIdentity(len(promptBytes), hex.EncodeToString(promptSum[:]))
	if err != nil {
		t.Fatal(err)
	}
	packetIdentity, err := ports.NewProviderPacketIdentity(len(packet.Bytes()), testStdinDigest(packet.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	transport, err := ports.NewTerminalProviderPacketTransportReceipt(
		packetIdentity,
		promptIdentity,
		promptIdentity,
	)
	if err != nil {
		t.Fatal(err)
	}
	stdinReceipt, err := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
	if err != nil {
		t.Fatal(err)
	}
	var finalTerm ports.ProcessFinalTermination
	if termination == ports.ProcessTerminationExited {
		finalTerm, err = ports.NewExitedProcessFinalTermination(exitCode)
	} else {
		sig, sigErr := ports.NewProcessSignal(15, "SIGTERM")
		if sigErr != nil {
			t.Fatal(sigErr)
		}
		finalTerm, err = ports.NewSignaledProcessFinalTermination(sig)
	}
	if err != nil {
		t.Fatal(err)
	}
	if !pgAbsent {
		now := time.Now().UTC()
		obs, err := ports.NewProviderProcessObservation(
			stdout, stderr, nil, ports.ProcessTerminationResidualProcessGroup, stdinReceipt, transport, now, now,
		)
		if err != nil {
			t.Fatal(err)
		}
		return obs
	}
	lifecycle, err := ports.NewProcessLifecycleReceipt(finalTerm, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	obs, err := ports.NewStartedProviderProcessObservation(
		stdout, stderr, termination, stdinReceipt, transport, lifecycle, now, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	return obs
}

func makeTerminalSessionObservation(
	t *testing.T,
	runner *fakeTerminalSessionRunner,
	req ports.TerminalExecutionRequest,
	input ports.TerminalExecutionObservationInput,
	termination ports.ProcessTermination,
	exitCode int,
	pgAbsent bool,
	stdout, stderr []byte,
) ports.TerminalExecutionObservation {
	t.Helper()
	if !input.Process.Valid() {
		input.Process = makeTerminalProcessObservation(t, req, termination, exitCode, pgAbsent, stdout, stderr)
	}
	if !input.RuntimeIdentity.Valid() {
		input.RuntimeIdentity = runner.identity
	}
	if input.PaneID == "" {
		input.PaneID = "pane-test-1"
	}
	if input.ProgramStatus != "" && !input.ExitedBeforeReport {
		input.Reported = true
	}
	obs, err := ports.NewTerminalExecutionObservation(input)
	if err != nil {
		t.Fatal(err)
	}
	return obs
}

// fakeMultiHomeNonOSCProfile is a second, non-OSC, multi-home terminal profile
// proving terminal_provider.go is genuinely provider-agnostic.
type fakeMultiHomeNonOSCProfile struct {
	requireNonce bool
	enableBash   bool
}

func (fakeMultiHomeNonOSCProfile) Family() string            { return FamilyGrok }
func (fakeMultiHomeNonOSCProfile) RequireOSCReporting() bool { return false }
func (p fakeMultiHomeNonOSCProfile) RequireCompletionNonce(terminalInvocationPurpose) bool {
	return p.requireNonce
}
func (fakeMultiHomeNonOSCProfile) OutputFilename(purpose terminalInvocationPurpose) string {
	switch purpose {
	case terminalPurposeExtraction:
		return stagedExtractionOutputFilename
	case terminalPurposeQualification:
		return stagedProbeOutputFilename
	default:
		return stagedOutputFilename
	}
}
func (fakeMultiHomeNonOSCProfile) StartupTimeout(terminalInvocationPurpose) time.Duration {
	return 10 * time.Second
}
func (fakeMultiHomeNonOSCProfile) CheckInInterval(terminalInvocationPurpose) time.Duration {
	return 5 * time.Second
}
func (fakeMultiHomeNonOSCProfile) TerminalSize() (int, int) { return 120, 40 }
func (fakeMultiHomeNonOSCProfile) PrepareDisposableHomes(inv terminalProfileInvocation) ([]ports.EnvironmentVariable, error) {
	configHome := filepath.Join(inv.HomeDir, ".fake-config")
	cacheHome := filepath.Join(inv.HomeDir, ".fake-cache")
	for _, dir := range []string{configHome, cacheHome} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(configHome, "profile.conf"), []byte("offline = true\n"), 0o600); err != nil {
		return nil, err
	}
	v1, err := ports.NewEnvironmentVariable("FAKE_CONFIG_HOME", configHome)
	if err != nil {
		return nil, err
	}
	v2, err := ports.NewEnvironmentVariable("FAKE_CACHE_HOME", cacheHome)
	if err != nil {
		return nil, err
	}
	return []ports.EnvironmentVariable{v1, v2}, nil
}
func (fakeMultiHomeNonOSCProfile) BuildArgv(inv terminalProfileInvocation) ([]string, error) {
	return []string{inv.Definition.Executable(), "--prompt-file", inv.PromptPath, "--out-file", inv.OutputPath}, nil
}
func (fakeMultiHomeNonOSCProfile) BuildInitialInput(terminalProfileInvocation) string { return "" }
func (p fakeMultiHomeNonOSCProfile) BuildPromptTrailer(inv terminalProfileInvocation) []byte {
	if !p.requireNonce {
		return nil
	}
	return []byte("\n" + terminalCompletionNoncePrefix + inv.CompletionNonce + "\n")
}
func (p fakeMultiHomeNonOSCProfile) ConfigureBoundary(base ports.LiveReadOnlyBoundary, inv terminalProfileInvocation) (ports.LiveReadOnlyBoundary, error) {
	b, err := ports.NewLiveReadOnlyBoundaryWithPaneTTY(base, inv.NativeHome)
	if err != nil {
		return ports.LiveReadOnlyBoundary{}, err
	}
	if p.enableBash {
		return ports.NewLiveReadOnlyBoundaryWithBashGate(b)
	}
	return b, nil
}

type terminalTestFixture struct {
	root          string
	namespaceRoot string
	nativeHome    ports.AnchoredRoot
	neutralCWD    ports.AnchoredRoot
	sourceRoot    ports.AnchoredRoot
	credRoot      ports.AnchoredRoot
	cpRoots       []ports.AnchoredRoot
	cpLiterals    []ports.AnchoredRoot
	namespaceEnv  []ports.EnvironmentVariable
	def           RuntimeDefinition
}

func newTerminalTestFixture(t *testing.T) terminalTestFixture {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	nsRoot := filepath.Join(base, "ns")
	nativeHomeDir := filepath.Join(base, "native-home")
	neutralDir := filepath.Join(nativeHomeDir, ".mulgae", "home")
	sourceDir := filepath.Join(base, "source")
	credDir := filepath.Join(nativeHomeDir, ".grok")
	for _, dir := range []string{
		filepath.Join(nsRoot, "home"),
		filepath.Join(nsRoot, "scratch"),
		filepath.Join(nsRoot, "tmp"),
		filepath.Join(nsRoot, "settings"),
		filepath.Join(nsRoot, "auth"),
		filepath.Join(nsRoot, "cache"),
		neutralDir,
		sourceDir,
		credDir,
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	nativeHome, err := ports.NewAnchoredRoot(nativeHomeDir)
	if err != nil {
		t.Fatal(err)
	}
	neutralCWD, err := ports.NewAnchoredRoot(neutralDir)
	if err != nil {
		t.Fatal(err)
	}
	sourceRoot, err := ports.NewAnchoredRoot(sourceDir)
	if err != nil {
		t.Fatal(err)
	}
	credRoot, err := ports.NewAnchoredRoot(credDir)
	if err != nil {
		t.Fatal(err)
	}
	cpRoots, cpLiterals, err := defaultControlPlanePathsForHome(nativeHome)
	if err != nil {
		t.Fatal(err)
	}
	def, err := NewRuntimeDefinition(FamilyGrok, "grok_test", "1.0.89", "/private/bin/grok", "", "grok_test", []string{"/private/bin/grok"}, nil, neutralDir, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return terminalTestFixture{
		root:          base,
		namespaceRoot: nsRoot,
		nativeHome:    nativeHome,
		neutralCWD:    neutralCWD,
		sourceRoot:    sourceRoot,
		credRoot:      credRoot,
		cpRoots:       cpRoots,
		cpLiterals:    cpLiterals,
		namespaceEnv:  directExecutionNamespaceEnvironment(t, nsRoot, filepath.Join(nsRoot, "home")),
		def:           def,
	}
}

func (f terminalTestFixture) openLaunchDir(t *testing.T) *os.File {
	t.Helper()
	dir, err := os.Open(f.neutralCWD.String())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func (f terminalTestFixture) baseRequest(t *testing.T, purpose terminalInvocationPurpose, packetBytes []byte) terminalDriverRequest {
	t.Helper()
	packet, err := ports.NewProviderPacketFromBytes(packetBytes)
	if err != nil {
		t.Fatal(err)
	}
	return terminalDriverRequest{
		Definition:           f.def,
		Purpose:              purpose,
		LiveScope:            domain.LiveSourceWorkspace,
		HasLiveScope:         purpose == terminalPurposeReview,
		Packet:               packet,
		NamespaceRoot:        f.namespaceRoot,
		NamespaceEnvironment: f.namespaceEnv,
		NeutralCWD:           f.neutralCWD,
		LaunchDirectory:      f.openLaunchDir(t),
		NativeHome:           f.nativeHome,
		SourceRoot:           f.sourceRoot,
		ReadOnlyRoots:        []ports.AnchoredRoot{f.sourceRoot, f.neutralCWD},
		CredentialRoots:      []ports.AnchoredRoot{f.credRoot},
		ControlPlaneRoots:    f.cpRoots,
		ControlPlaneLiterals: f.cpLiterals,
		Timeout:              2 * time.Minute,
		RegistryGeneration:   "gen-test-1",
	}
}

func extractPromptNonce(t *testing.T, promptPath string) string {
	t.Helper()
	raw, err := os.ReadFile(promptPath)
	if err != nil {
		t.Fatal(err)
	}
	idx := strings.LastIndex(string(raw), terminalCompletionNoncePrefix)
	if idx < 0 {
		t.Fatalf("prompt %s missing completion nonce prefix", promptPath)
	}
	rest := string(raw)[idx+len(terminalCompletionNoncePrefix):]
	line, _, _ := strings.Cut(rest, "\n")
	return strings.TrimSpace(line)
}

func findStagedOutputPath(t *testing.T, nsRoot, filename string) string {
	t.Helper()
	outputParent := filepath.Join(nsRoot, "scratch", stagedOutputParentDirectoryName)
	entries, err := os.ReadDir(outputParent)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected 1 staging dir under %s, got %v (%v)", outputParent, entries, err)
	}
	return filepath.Join(outputParent, entries[0].Name(), filename)
}

func TestTerminalProviderNonOSCMultiHomeProfileSuccessAndExtensibility(t *testing.T) {
	fx := newTerminalTestFixture(t)
	profile := fakeMultiHomeNonOSCProfile{requireNonce: true}
	runner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
	packetBytes := []byte("review payload without trailing mutation")

	var capturedPromptMode os.FileMode
	var capturedPromptPrefixOK bool
	var capturedInputInRO bool
	var capturedEnv map[string]string
	var capturedLabels map[string]string
	var capturedOutputPath string

	runner.runFunc = func(_ context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
		if req.RequireOSCReporting() {
			t.Fatal("non-OSC profile had RequireOSCReporting=true")
		}
		if req.InitialInput() != "" {
			t.Fatalf("non-OSC profile had non-empty initial input %q", req.InitialInput())
		}
		info, err := os.Lstat(req.PromptFilePath().String())
		if err != nil {
			t.Fatal(err)
		}
		capturedPromptMode = info.Mode().Perm()
		promptRaw, err := os.ReadFile(req.PromptFilePath().String())
		if err != nil {
			t.Fatal(err)
		}
		capturedPromptPrefixOK = bytes.HasPrefix(promptRaw, packetBytes)
		boundary, guarded := req.Process().LiveReadOnlyBoundary()
		if !guarded || !boundary.PaneTTY() || boundary.OwnedPTY() || boundary.BashGate() {
			t.Fatalf("unexpected non-OSC boundary guarded=%t paneTTY=%t ownedPTY=%t bash=%t", guarded, boundary.PaneTTY(), boundary.OwnedPTY(), boundary.BashGate())
		}
		inputParent := filepath.Join(fx.namespaceRoot, "scratch", terminalPromptParentDirName)
		capturedInputInRO = anchoredContains(boundary.ReadOnlyRoots(), inputParent)
		capturedEnv = credentialSourceEnvironment(req.Process().Environment())
		capturedLabels = req.Labels()

		nonce := extractPromptNonce(t, req.PromptFilePath().String())
		capturedOutputPath = findStagedOutputPath(t, fx.namespaceRoot, stagedOutputFilename)
		body := "# Non-OSC Review\n\nAll good.\n" + terminalCompletionNoncePrefix + nonce + "\n"
		if err := os.WriteFile(capturedOutputPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return makeTerminalSessionObservation(t, runner, req, ports.TerminalExecutionObservationInput{
			Reported:  false,
			TurnCount: 0,
		}, ports.ProcessTerminationExited, 0, true, nil, nil), nil
	}

	req := fx.baseRequest(t, terminalPurposeReview, packetBytes)
	res, err := executeTerminalInvocation(context.Background(), runner, profile, req)
	if err != nil {
		t.Fatalf("non-OSC multi-home terminal execution failed: %v", err)
	}
	if capturedPromptMode != 0o400 {
		t.Fatalf("prompt.md mode = %04o, want 0400", capturedPromptMode)
	}
	if !capturedPromptPrefixOK {
		t.Fatal("prompt.md did not preserve packet.Bytes() as exact prefix")
	}
	if !capturedInputInRO {
		t.Fatal("<scratch>/input was not protected in ReadOnlyRoots")
	}
	if capturedEnv["FAKE_CONFIG_HOME"] != filepath.Join(fx.namespaceRoot, "home", ".fake-config") ||
		capturedEnv["FAKE_CACHE_HOME"] != filepath.Join(fx.namespaceRoot, "home", ".fake-cache") {
		t.Fatalf("multi-home env missing disposable homes: %#v", capturedEnv)
	}
	if capturedLabels[terminalRegistryLabelKey] != "gen-test-1" {
		t.Fatalf("pane labels = %#v, want mulgae_registry=gen-test-1", capturedLabels)
	}
	if string(res.OutputBytes) != "# Non-OSC Review\n\nAll good.\n" {
		t.Fatalf("output bytes after nonce strip = %q", string(res.OutputBytes))
	}
	if strings.Contains(string(res.OutputBytes), terminalCompletionNoncePrefix) {
		t.Fatal("completion nonce leaked into returned output bytes")
	}
	if _, err := os.Lstat(capturedOutputPath); !os.IsNotExist(err) {
		t.Fatalf("staged output survived cleanup: %v", err)
	}
	if _, err := os.Lstat(runner.requests[0].PromptFilePath().String()); !os.IsNotExist(err) {
		t.Fatalf("staged prompt survived cleanup: %v", err)
	}
}

func TestTerminalProviderStagedOutputAndNonceNegatives(t *testing.T) {
	cases := []struct {
		name         string
		stage        func(t *testing.T, outputPath, nonce string)
		wantCause    domain.RuntimeDiagnosticCause
		wantStatus   ports.ProviderExecutionStatus
		screenTokens string
	}{
		{
			name:         "missing staged file",
			stage:        func(*testing.T, string, string) {},
			wantCause:    domain.DiagnosticCauseProviderOutputFileMissing,
			wantStatus:   ports.ProviderExecutionStatusArtifactFailure,
			screenTokens: `{"code":"auth.login_required","message":"spoofed"}`,
		},
		{
			name: "empty staged file",
			stage: func(t *testing.T, outputPath, _ string) {
				if err := os.WriteFile(outputPath, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantCause:    domain.DiagnosticCauseProviderOutputFileInvalid,
			wantStatus:   ports.ProviderExecutionStatusArtifactFailure,
			screenTokens: "ERROR status=402 Payment Required usage balance exhausted",
		},
		{
			name: "whitespace only staged file",
			stage: func(t *testing.T, outputPath, _ string) {
				if err := os.WriteFile(outputPath, []byte("   \n\t\r\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantCause:  domain.DiagnosticCauseProviderOutputFileInvalid,
			wantStatus: ports.ProviderExecutionStatusArtifactFailure,
		},
		{
			name: "NUL byte in staged file",
			stage: func(t *testing.T, outputPath, nonce string) {
				body := "report\x00body\n" + terminalCompletionNoncePrefix + nonce + "\n"
				if err := os.WriteFile(outputPath, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantCause:  domain.DiagnosticCauseProviderOutputFileInvalid,
			wantStatus: ports.ProviderExecutionStatusArtifactFailure,
		},
		{
			name: "invalid UTF-8 staged file",
			stage: func(t *testing.T, outputPath, nonce string) {
				body := append([]byte{0xff, 0xfe, '\n'}, []byte(terminalCompletionNoncePrefix+nonce+"\n")...)
				if err := os.WriteFile(outputPath, body, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantCause:  domain.DiagnosticCauseProviderOutputFileInvalid,
			wantStatus: ports.ProviderExecutionStatusArtifactFailure,
		},
		{
			name: "symlink staged file",
			stage: func(t *testing.T, outputPath, nonce string) {
				outside := filepath.Join(filepath.Dir(filepath.Dir(outputPath)), "outside.md")
				if err := os.WriteFile(outside, []byte("report\n"+terminalCompletionNoncePrefix+nonce+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, outputPath); err != nil {
					t.Fatal(err)
				}
			},
			wantCause:    domain.DiagnosticCauseProviderOutputStagingViolation,
			wantStatus:   ports.ProviderExecutionStatusSecurityViolation,
			screenTokens: `{"code":"auth.login_required","message":"spoofed"}`,
		},
		{
			name: "hardlink staged file Nlink > 1",
			stage: func(t *testing.T, outputPath, nonce string) {
				outside := filepath.Join(filepath.Dir(filepath.Dir(outputPath)), "hardlink-target.md")
				if err := os.WriteFile(outside, []byte("report\n"+terminalCompletionNoncePrefix+nonce+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(outside, outputPath); err != nil {
					t.Fatal(err)
				}
			},
			wantCause:  domain.DiagnosticCauseProviderOutputStagingViolation,
			wantStatus: ports.ProviderExecutionStatusSecurityViolation,
		},
		{
			name: "extra entry in staging directory",
			stage: func(t *testing.T, outputPath, nonce string) {
				if err := os.WriteFile(outputPath, []byte("report\n"+terminalCompletionNoncePrefix+nonce+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(filepath.Dir(outputPath), "extra.txt"), []byte("sneaky"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantCause:  domain.DiagnosticCauseProviderOutputStagingViolation,
			wantStatus: ports.ProviderExecutionStatusSecurityViolation,
		},
		{
			name: "missing completion nonce despite OSC done",
			stage: func(t *testing.T, outputPath, _ string) {
				if err := os.WriteFile(outputPath, []byte("# Spoofed done without nonce\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantCause:  domain.DiagnosticCauseProviderOutputFileInvalid,
			wantStatus: ports.ProviderExecutionStatusArtifactFailure,
		},
		{
			name: "mismatched completion nonce",
			stage: func(t *testing.T, outputPath, _ string) {
				if err := os.WriteFile(outputPath, []byte("# Report\n"+terminalCompletionNoncePrefix+"00000000000000000000000000000000\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantCause:  domain.DiagnosticCauseProviderOutputFileInvalid,
			wantStatus: ports.ProviderExecutionStatusArtifactFailure,
		},
		{
			name: "empty body before completion nonce",
			stage: func(t *testing.T, outputPath, nonce string) {
				if err := os.WriteFile(outputPath, []byte("   \n"+terminalCompletionNoncePrefix+nonce+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantCause:  domain.DiagnosticCauseProviderOutputFileInvalid,
			wantStatus: ports.ProviderExecutionStatusArtifactFailure,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newTerminalTestFixture(t)
			runner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
			runner.runFunc = func(_ context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
				nonce := extractPromptNonce(t, req.PromptFilePath().String())
				outputPath := findStagedOutputPath(t, fx.namespaceRoot, stagedOutputFilename)
				tc.stage(t, outputPath, nonce)
				return makeTerminalSessionObservation(t, runner, req, ports.TerminalExecutionObservationInput{
					ProgramStatus: ports.TerminalProgramStatusDone,
					TurnCount:     1,
					ScreenCapture: []byte(tc.screenTokens),
				}, ports.ProcessTerminationExited, 0, true, nil, []byte(tc.screenTokens)), nil
			}
			_, err := executeTerminalInvocation(context.Background(), runner, grokTerminalProfile{}, fx.baseRequest(t, terminalPurposeReview, []byte("prompt")))
			var df *terminalDriverFailure
			if !errors.As(err, &df) {
				t.Fatalf("error = %T (%v), want *terminalDriverFailure", err, err)
			}
			if df.Cause() != tc.wantCause || df.Status() != tc.wantStatus {
				t.Fatalf("cause=%q status=%q, want %q / %q (err=%v)", df.Cause(), df.Status(), tc.wantCause, tc.wantStatus, err)
			}
		})
	}
}

func TestTerminalProviderB1Control5StabilityAndSurvivorChecks(t *testing.T) {
	t.Run("mtime or ctime drift fails closed when BashGate active", func(t *testing.T) {
		fx := newTerminalTestFixture(t)
		runner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
		var outputPath string
		runner.runFunc = func(_ context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
			boundary, guarded := req.Process().LiveReadOnlyBoundary()
			if !guarded || !boundary.BashGate() {
				t.Fatal("commit scope review did not enable B-1 BashGate")
			}
			nonce := extractPromptNonce(t, req.PromptFilePath().String())
			outputPath = findStagedOutputPath(t, fx.namespaceRoot, stagedOutputFilename)
			if err := os.WriteFile(outputPath, []byte("report\n"+terminalCompletionNoncePrefix+nonce+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return makeTerminalSessionObservation(t, runner, req, ports.TerminalExecutionObservationInput{
				ProgramStatus: ports.TerminalProgramStatusDone,
				TurnCount:     1,
			}, ports.ProcessTerminationExited, 0, true, nil, nil), nil
		}
		req := fx.baseRequest(t, terminalPurposeReview, []byte("commit review"))
		req.LiveScope = domain.LiveSourceCommit
		req.StabilityWindow = 10 * time.Millisecond
		req.AfterFirstStatHook = func() {
			future := time.Now().Add(2 * time.Second)
			_ = os.Chtimes(outputPath, future, future)
		}
		_, err := executeTerminalInvocation(context.Background(), runner, grokTerminalProfile{}, req)
		var df *terminalDriverFailure
		if !errors.As(err, &df) || df.Cause() != domain.DiagnosticCauseProviderOutputStagingViolation || df.Status() != ports.ProviderExecutionStatusSecurityViolation {
			t.Fatalf("B-1 mtime drift result = %v, want security_violation / provider_output_staging_violation", err)
		}
	})

	t.Run("survivor check hook fails closed when BashGate active", func(t *testing.T) {
		fx := newTerminalTestFixture(t)
		runner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
		var capturedSentinel string
		runner.runFunc = func(_ context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
			env := credentialSourceEnvironment(req.Process().Environment())
			capturedSentinel = env[terminalProfileSentinelEnvName]
			nonce := extractPromptNonce(t, req.PromptFilePath().String())
			outputPath := findStagedOutputPath(t, fx.namespaceRoot, stagedOutputFilename)
			if err := os.WriteFile(outputPath, []byte("report\n"+terminalCompletionNoncePrefix+nonce+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return makeTerminalSessionObservation(t, runner, req, ports.TerminalExecutionObservationInput{
				ProgramStatus: ports.TerminalProgramStatusDone,
				TurnCount:     1,
			}, ports.ProcessTerminationExited, 0, true, nil, nil), nil
		}
		req := fx.baseRequest(t, terminalPurposeReview, []byte("stage review"))
		req.LiveScope = domain.LiveSourceStage
		req.StabilityWindow = 5 * time.Millisecond
		var checkedSentinel string
		req.SurvivorCheck = func(sentinel string) error {
			checkedSentinel = sentinel
			return errors.New("surviving child matched profile sentinel")
		}
		_, err := executeTerminalInvocation(context.Background(), runner, grokTerminalProfile{}, req)
		var df *terminalDriverFailure
		if !errors.As(err, &df) || df.Cause() != domain.DiagnosticCauseProviderOutputStagingViolation || df.Status() != ports.ProviderExecutionStatusSecurityViolation {
			t.Fatalf("B-1 survivor result = %v, want security_violation / provider_output_staging_violation", err)
		}
		if capturedSentinel == "" || checkedSentinel != capturedSentinel {
			t.Fatalf("sentinel mismatch: env=%q checked=%q", capturedSentinel, checkedSentinel)
		}
	})

	t.Run("real Darwin procargs2 survivor scanner detects live same-UID sentinel child", func(t *testing.T) {
		sentinel, err := terminalRandomHex(16)
		if err != nil {
			t.Fatal(err)
		}
		// Use a non-SIP binary (this Go test executable running a sleeping test
		// subprocess, or /bin/sh with the staging needle in argv) so KERN_PROCARGS2
		// exposes envp as it does for real provider processes like grok.
		selfBin, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(selfBin, "-test.run=^TestTerminalSentinelChildHelper$")
		cmd.Env = []string{
			"PATH=/usr/bin:/bin",
			"MULGAE_TEST_SLEEP_HELPER=1",
			terminalProfileSentinelEnvName + "=" + sentinel,
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		var killCmdOnce sync.Once
		killCmd := func() {
			killCmdOnce.Do(func() {
				if cmd.Process != nil {
					_ = cmd.Process.Kill()
					_, _ = cmd.Process.Wait()
				}
			})
		}
		defer killCmd()
		var scanErr error
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			scanErr = checkSameUIDProfileSentinelSurvivors(sentinel)
			if scanErr != nil {
				break
			}
			time.Sleep(15 * time.Millisecond)
		}
		if scanErr == nil {
			t.Fatal("checkSameUIDProfileSentinelSurvivors failed to detect live non-SIP child carrying profile sentinel in envp")
		}
		killCmd()
		if err := checkSameUIDProfileSentinelSurvivors(sentinel); err != nil {
			t.Fatalf("checkSameUIDProfileSentinelSurvivors reported phantom survivor after child exit: %v", err)
		}

		// Also verify Apple SIP /bin/sh referencing a staging path in argv is detected!
		stagingMarker := "/private/tmp/mulgae-b1-staging-needle-" + sentinel
		sipCmd := exec.Command("/bin/sh", "-c", "sleep 30; true # "+stagingMarker)
		sipCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := sipCmd.Start(); err != nil {
			t.Fatal(err)
		}
		var killSipOnce sync.Once
		killSipGroup := func() {
			killSipOnce.Do(func() {
				if sipCmd.Process != nil {
					_ = syscall.Kill(-sipCmd.Process.Pid, syscall.SIGKILL)
					_, _ = sipCmd.Process.Wait()
				}
			})
		}
		defer killSipGroup()
		scanErr = nil
		deadline = time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			scanErr = checkSameUIDProfileSentinelSurvivors("unused-sentinel-"+sentinel, stagingMarker)
			if scanErr != nil {
				break
			}
			time.Sleep(15 * time.Millisecond)
		}
		if scanErr == nil {
			t.Fatal("checkSameUIDProfileSentinelSurvivors failed to detect live Apple SIP /bin/sh referencing staging path")
		}
		killSipGroup()
	})
}

func TestTerminalSentinelChildHelper(t *testing.T) {
	if os.Getenv("MULGAE_TEST_SLEEP_HELPER") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
}

func TestTerminalProviderClassifiesCoreStatesAndLaunchFailures(t *testing.T) {
	t.Run("ExitedBeforeReport is spawn_failed independent of exit code 10 vs 125 vs 0", func(t *testing.T) {
		for _, exitCode := range []int{10, 125, 0, 1} {
			t.Run(fmt.Sprintf("exit_%d", exitCode), func(t *testing.T) {
				fx := newTerminalTestFixture(t)
				runner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
				runner.runFunc = func(_ context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
					return makeTerminalSessionObservation(t, runner, req, ports.TerminalExecutionObservationInput{
						ExitedBeforeReport: true,
						ScreenCapture:      []byte(`{"code":"auth.login_required"}`),
					}, ports.ProcessTerminationExited, exitCode, true, nil, []byte(`{"code":"auth.login_required"}`)), nil
				}
				_, err := executeTerminalInvocation(context.Background(), runner, grokTerminalProfile{}, fx.baseRequest(t, terminalPurposeReview, []byte("prompt")))
				var df *terminalDriverFailure
				if !errors.As(err, &df) || df.Cause() != domain.DiagnosticCauseProviderSpawnFailed || df.Status() != ports.ProviderExecutionStatusUnavailable {
					t.Fatalf("exit=%d result = %v, want unavailable/provider_spawn_failed", exitCode, err)
				}
			})
		}
	})

	t.Run("ProcessGroupAbsent=false fails closed before reading staged output", func(t *testing.T) {
		fx := newTerminalTestFixture(t)
		runner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
		runner.runFunc = func(_ context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
			nonce := extractPromptNonce(t, req.PromptFilePath().String())
			outputPath := findStagedOutputPath(t, fx.namespaceRoot, stagedOutputFilename)
			if err := os.WriteFile(outputPath, []byte("valid body\n"+terminalCompletionNoncePrefix+nonce+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return makeTerminalSessionObservation(t, runner, req, ports.TerminalExecutionObservationInput{
				ProgramStatus: ports.TerminalProgramStatusDone,
				TurnCount:     1,
			}, ports.ProcessTerminationResidualProcessGroup, 0, false, nil, nil), nil
		}
		_, err := executeTerminalInvocation(context.Background(), runner, grokTerminalProfile{}, fx.baseRequest(t, terminalPurposeReview, []byte("prompt")))
		var df *terminalDriverFailure
		if !errors.As(err, &df) || df.Status() != ports.ProviderExecutionStatusSecurityViolation || df.Cause() != domain.DiagnosticCauseProcessGroupCleanupFailed {
			t.Fatalf("residual pg result = %v, want security_violation/process_group_cleanup_failed", err)
		}
	})

	stateCases := []struct {
		name           string
		programStatus  ports.TerminalProgramStatus
		blockedKind    ports.TerminalBlockedKind
		turnCount      int
		screen         string
		wantStatus     ports.ProviderExecutionStatus
		wantCause      domain.RuntimeDiagnosticCause
		wantLoginError bool
	}{
		{
			name:           "blocked auth",
			programStatus:  ports.TerminalProgramStatusBlocked,
			blockedKind:    ports.TerminalBlockedKindAuth,
			wantStatus:     ports.ProviderExecutionStatusAuthentication,
			wantCause:      domain.DiagnosticCauseLoginRequired,
			wantLoginError: true,
		},
		{
			name:          "blocked quota",
			programStatus: ports.TerminalProgramStatusBlocked,
			blockedKind:   ports.TerminalBlockedKindQuota,
			wantStatus:    ports.ProviderExecutionStatusQuota,
			wantCause:     domain.DiagnosticCauseQuotaExceeded,
		},
		{
			name:          "blocked rate_limit",
			programStatus: ports.TerminalProgramStatusBlocked,
			blockedKind:   ports.TerminalBlockedKindRateLimit,
			wantStatus:    ports.ProviderExecutionStatusRateLimit,
			wantCause:     domain.DiagnosticCauseRateLimited,
		},
		{
			name:          "blocked permission",
			programStatus: ports.TerminalProgramStatusBlocked,
			blockedKind:   ports.TerminalBlockedKindPermission,
			wantStatus:    ports.ProviderExecutionStatusAuthentication,
			wantCause:     domain.DiagnosticCausePermissionDenied,
		},
		{
			name:          "error refined by quota screen capture",
			programStatus: ports.TerminalProgramStatusError,
			screen:        "ERROR status=402 Payment Required usage balance exhausted",
			wantStatus:    ports.ProviderExecutionStatusQuota,
			wantCause:     domain.DiagnosticCauseQuotaExceeded,
		},
		{
			name:          "error without native token stays provider_execution_failed",
			programStatus: ports.TerminalProgramStatusError,
			screen:        "generic unexpected failure",
			wantStatus:    ports.ProviderExecutionStatusUnavailable,
			wantCause:     domain.DiagnosticCauseProviderExecutionFailed,
		},
		{
			name:          "OSC done with zero turns rejected as turn_failed",
			programStatus: ports.TerminalProgramStatusDone,
			turnCount:     0,
			wantStatus:    ports.ProviderExecutionStatusUnavailable,
			wantCause:     domain.DiagnosticCauseProviderTurnFailed,
		},
		{
			name:          "OSC working never reached done",
			programStatus: ports.TerminalProgramStatusWorking,
			turnCount:     1,
			wantStatus:    ports.ProviderExecutionStatusUnavailable,
			wantCause:     domain.DiagnosticCauseProviderTurnFailed,
		},
	}

	for _, tc := range stateCases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newTerminalTestFixture(t)
			runner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
			runner.runFunc = func(_ context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
				return makeTerminalSessionObservation(t, runner, req, ports.TerminalExecutionObservationInput{
					ProgramStatus: tc.programStatus,
					BlockedKind:   tc.blockedKind,
					TurnCount:     tc.turnCount,
					ScreenCapture: []byte(tc.screen),
				}, ports.ProcessTerminationExited, 0, true, nil, []byte(tc.screen)), nil
			}
			_, err := executeTerminalInvocation(context.Background(), runner, grokTerminalProfile{}, fx.baseRequest(t, terminalPurposeReview, []byte("prompt")))
			var df *terminalDriverFailure
			if !errors.As(err, &df) {
				t.Fatalf("error = %T (%v), want *terminalDriverFailure", err, err)
			}
			if df.Status() != tc.wantStatus || df.Cause() != tc.wantCause {
				t.Fatalf("status=%q cause=%q, want %q / %q", df.Status(), df.Cause(), tc.wantStatus, tc.wantCause)
			}
			if tc.wantLoginError && !errors.Is(err, ports.ErrProviderLoginRequired) {
				t.Fatalf("expected ErrProviderLoginRequired wrap, got %v", err)
			}
		})
	}
}

func TestCarveTerminalStartupTimeout(t *testing.T) {
	for _, tc := range []struct {
		total, requested, want time.Duration
		wantErr                bool
	}{
		{3 * time.Minute, 45 * time.Second, 45 * time.Second, false},
		{60 * time.Second, 45 * time.Second, 30 * time.Second, false},
		{2 * time.Second, 45 * time.Second, time.Second, false},
		{10 * time.Millisecond, 45 * time.Second, 5 * time.Millisecond, false},
		{time.Nanosecond, 45 * time.Second, 0, true},
		{0, 45 * time.Second, 0, true},
	} {
		got, err := carveTerminalStartupTimeout(tc.total, tc.requested)
		if (err != nil) != tc.wantErr {
			t.Fatalf("carve(%s, %s) err=%v, wantErr=%t", tc.total, tc.requested, err, tc.wantErr)
		}
		if !tc.wantErr && (got != tc.want || got <= 0 || got >= tc.total) {
			t.Fatalf("carve(%s, %s) = %s, want %s strictly inside (0, total)", tc.total, tc.requested, got, tc.want)
		}
	}
}

func TestTerminalProviderUnsolicitedSignalAfterReportProducesValidInternalFailureObservation(t *testing.T) {
	for _, tc := range []struct {
		name          string
		programStatus ports.TerminalProgramStatus
		turnCount     int
		sigNum        int
		sigName       string
	}{
		{name: "SIGSEGV while working", programStatus: ports.TerminalProgramStatusWorking, turnCount: 0, sigNum: 11, sigName: "SIGSEGV"},
		{name: "SIGKILL after done without teardown receipt", programStatus: ports.TerminalProgramStatusDone, turnCount: 1, sigNum: 9, sigName: "SIGKILL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newTerminalTestFixture(t)
			runner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
			runner.runFunc = func(_ context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
				binding, ok := req.Process().ProviderPacketBinding()
				if !ok {
					t.Fatal("missing packet binding")
				}
				promptBytes, err := os.ReadFile(req.PromptFilePath().String())
				if err != nil {
					t.Fatal(err)
				}
				promptSum := sha256.Sum256(promptBytes)
				promptID, err := ports.NewProviderPacketIdentity(len(promptBytes), hex.EncodeToString(promptSum[:]))
				if err != nil {
					t.Fatal(err)
				}
				packetID, err := ports.NewProviderPacketIdentity(len(binding.Packet().Bytes()), testStdinDigest(binding.Packet().Bytes()))
				if err != nil {
					t.Fatal(err)
				}
				transport, err := ports.NewTerminalProviderPacketTransportReceipt(packetID, promptID, promptID)
				if err != nil {
					t.Fatal(err)
				}
				stdinReceipt, err := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
				if err != nil {
					t.Fatal(err)
				}
				sig, err := ports.NewProcessSignal(tc.sigNum, tc.sigName)
				if err != nil {
					t.Fatal(err)
				}
				finalTerm, err := ports.NewSignaledProcessFinalTermination(sig)
				if err != nil {
					t.Fatal(err)
				}
				// No Mulgae teardown signal requests => TerminalSessionCompleted() == false.
				lifecycle, err := ports.NewProcessLifecycleReceipt(finalTerm, true, nil)
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC()
				procObs, err := ports.NewStartedProviderProcessObservation(
					nil, nil, ports.ProcessTerminationSignaled, stdinReceipt, transport, lifecycle, now, now,
				)
				if err != nil {
					t.Fatal(err)
				}
				return ports.NewTerminalExecutionObservation(ports.TerminalExecutionObservationInput{
					Process:         procObs,
					RuntimeIdentity: runner.identity,
					PaneID:          "pane-sig-after-report",
					Reported:        true,
					ProgramStatus:   tc.programStatus,
					TurnCount:       tc.turnCount,
				})
			}

			inv := testInvocation(t, "grok_sig")
			res, err := executeTerminalInvocation(context.Background(), runner, grokTerminalProfile{}, fx.baseRequest(t, terminalPurposeReview, inv.Packet().Bytes()))
			var df *terminalDriverFailure
			if !errors.As(err, &df) {
				t.Fatalf("error = %T (%v), want *terminalDriverFailure", err, err)
			}
			if df.Status() != ports.ProviderExecutionStatusInternalFailure ||
				df.Diagnostic() != "process_internal" ||
				df.Cause() != domain.DiagnosticCauseProviderExecutionFailed {
				t.Fatalf("driver failure = status:%q diag:%q cause:%q, want internal_failure/process_internal/provider_execution_failed",
					df.Status(), df.Diagnostic(), df.Cause())
			}
			// Verify the resulting ProviderExecutionObservation passes Validate().
			obs, obsErr := ports.NewFailedProviderExecutionObservationWithCause(
				df.Status(), inv, res.Process, df.Diagnostic(), df.Cause(), df.CleanupCause(),
			)
			if obsErr != nil {
				t.Fatalf("NewFailedProviderExecutionObservationWithCause rejected unsolicited post-report signal: %v", obsErr)
			}
			if obs.Status() != ports.ProviderExecutionStatusInternalFailure {
				t.Fatalf("observation status = %q, want internal_failure", obs.Status())
			}
		})
	}
}

func TestVerifyAndStripCompletionNonceRejectsInBodyLeakageAndUpdatesReceipt(t *testing.T) {
	t.Run("rejects duplicate completion nonce line inside body", func(t *testing.T) {
		const nonce = "abcdef0123456789abcdef0123456789"
		raw := []byte("# Review\n\n" + terminalCompletionNoncePrefix + nonce + "\nTrailing body\n" + terminalCompletionNoncePrefix + nonce + "\n")
		if _, err := verifyAndStripCompletionNonce(raw, nonce); err == nil {
			t.Fatal("verifyAndStripCompletionNonce accepted duplicate completion nonce inside body")
		} else if stagedOutputCause(err) != domain.DiagnosticCauseProviderOutputFileInvalid {
			t.Fatalf("cause = %q, want provider_output_file_invalid", stagedOutputCause(err))
		}
	})

	t.Run("rejects raw nonce token leaked inside body", func(t *testing.T) {
		const nonce = "0123456789abcdef0123456789abcdef"
		raw := []byte("# Review\nLeaked token " + nonce + " in prose\n" + terminalCompletionNoncePrefix + nonce + "\n")
		if _, err := verifyAndStripCompletionNonce(raw, nonce); err == nil {
			t.Fatal("verifyAndStripCompletionNonce accepted raw nonce substring inside body")
		} else if stagedOutputCause(err) != domain.DiagnosticCauseProviderOutputFileInvalid {
			t.Fatalf("cause = %q, want provider_output_file_invalid", stagedOutputCause(err))
		}
	})

	t.Run("recomputes StagedReceipt over stripped accepted bytes", func(t *testing.T) {
		fx := newTerminalTestFixture(t)
		runner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
		runner.runFunc = func(_ context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
			nonce := extractPromptNonce(t, req.PromptFilePath().String())
			outputPath := findStagedOutputPath(t, fx.namespaceRoot, stagedOutputFilename)
			if err := os.WriteFile(outputPath, []byte("# Clean Report\n\nNo findings.\n"+terminalCompletionNoncePrefix+nonce+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return makeTerminalSessionObservation(t, runner, req, ports.TerminalExecutionObservationInput{
				ProgramStatus: ports.TerminalProgramStatusDone,
				TurnCount:     1,
			}, ports.ProcessTerminationExited, 0, true, nil, nil), nil
		}
		res, err := executeTerminalInvocation(context.Background(), runner, grokTerminalProfile{}, fx.baseRequest(t, terminalPurposeReview, []byte("review prompt")))
		if err != nil {
			t.Fatalf("executeTerminalInvocation failed: %v", err)
		}
		wantSum := sha256.Sum256(res.OutputBytes)
		wantDigest := "sha256:" + hex.EncodeToString(wantSum[:])
		if res.StagedReceipt.SHA256() != wantDigest || res.StagedReceipt.ByteLength() != int64(len(res.OutputBytes)) {
			t.Fatalf("StagedReceipt = (%s, %d), want (%s, %d) matching stripped OutputBytes",
				res.StagedReceipt.SHA256(), res.StagedReceipt.ByteLength(), wantDigest, len(res.OutputBytes))
		}
	})
}

func TestTerminalProviderStagedPromptParentAndRunnerDigestNegativeCases(t *testing.T) {
	t.Run("rejects symlinked scratch input parent before RunTerminal and closes launchDir", func(t *testing.T) {
		fx := newTerminalTestFixture(t)
		decoyDir := filepath.Join(fx.namespaceRoot, "decoy-input")
		if err := os.MkdirAll(decoyDir, 0o700); err != nil {
			t.Fatal(err)
		}
		inputParent := filepath.Join(fx.namespaceRoot, "scratch", terminalPromptParentDirName)
		if err := os.Symlink(decoyDir, inputParent); err != nil {
			t.Fatal(err)
		}
		runner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
		req := fx.baseRequest(t, terminalPurposeReview, []byte("prompt"))
		launchFD := int(req.LaunchDirectory.Fd())
		if _, err := executeTerminalInvocation(context.Background(), runner, grokTerminalProfile{}, req); err == nil {
			t.Fatal("symlinked <scratch>/input parent unexpectedly succeeded")
		}
		if len(runner.requests) != 0 {
			t.Fatalf("RunTerminal called %d times on symlinked input parent, want 0", len(runner.requests))
		}
		var st unix.Stat_t
		if err := unix.Fstat(launchFD, &st); !errors.Is(err, unix.EBADF) {
			t.Fatalf("launchDir FD %d was not closed on staged-prompt parent rejection (fstat err=%v)", launchFD, err)
		}
	})

	for _, mode := range []os.FileMode{0o755, 0o777} {
		t.Run(fmt.Sprintf("rejects non-private scratch input parent mode %#o before RunTerminal", mode), func(t *testing.T) {
			fx := newTerminalTestFixture(t)
			inputParent := filepath.Join(fx.namespaceRoot, "scratch", terminalPromptParentDirName)
			if err := os.Mkdir(inputParent, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(inputParent, mode); err != nil {
				t.Fatal(err)
			}
			runner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
			req := fx.baseRequest(t, terminalPurposeReview, []byte("prompt"))
			launchFD := int(req.LaunchDirectory.Fd())
			if _, err := executeTerminalInvocation(context.Background(), runner, grokTerminalProfile{}, req); err == nil {
				t.Fatalf("mode %#o <scratch>/input parent unexpectedly succeeded", mode)
			}
			if len(runner.requests) != 0 {
				t.Fatalf("RunTerminal called %d times on mode %#o input parent, want 0", len(runner.requests), mode)
			}
			var st unix.Stat_t
			if err := unix.Fstat(launchFD, &st); !errors.Is(err, unix.EBADF) {
				t.Fatalf("launchDir FD %d was not closed on mode %#o input parent rejection (fstat err=%v)", launchFD, mode, err)
			}
		})
	}

	for _, cause := range []domain.RuntimeDiagnosticCause{
		domain.DiagnosticCausePromptFilePreStartFailed,
		domain.DiagnosticCausePromptFilePostEndFailed,
	} {
		t.Run("runner "+string(cause)+" maps to SecurityViolation with staged output unread", func(t *testing.T) {
			fx := newTerminalTestFixture(t)
			runner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
			runner.runFunc = func(_ context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
				nonce := extractPromptNonce(t, req.PromptFilePath().String())
				outputPath := findStagedOutputPath(t, fx.namespaceRoot, stagedOutputFilename)
				if err := os.WriteFile(outputPath, []byte("DO NOT READ\n"+terminalCompletionNoncePrefix+nonce+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				procErr, buildErr := ports.NewProcessExecutionError(cause, "", nil, nil, errors.New("prompt digest mismatch"))
				if buildErr != nil {
					t.Fatal(buildErr)
				}
				return ports.TerminalExecutionObservation{}, procErr
			}
			res, err := executeTerminalInvocation(context.Background(), runner, grokTerminalProfile{}, fx.baseRequest(t, terminalPurposeReview, []byte("prompt")))
			if err == nil {
				t.Fatalf("expected error for %s", cause)
			}
			if len(res.OutputBytes) != 0 {
				t.Fatalf("staged output was read despite %s: %q", cause, res.OutputBytes)
			}
			gotCause, _ := providerRunCauses(err)
			if gotCause != cause {
				t.Fatalf("providerRunCauses = %q, want %q", gotCause, cause)
			}
			gotStatus, gotDiag := providerFailureProjection(gotCause)
			if gotStatus != ports.ProviderExecutionStatusSecurityViolation || gotDiag != "process_security" {
				t.Fatalf("projection = (%q, %q), want (security_violation, process_security)", gotStatus, gotDiag)
			}
		})
	}
}

func TestTerminalProviderPreStartOutcomesAndStartedPaneResidualSecurity(t *testing.T) {
	buildNoLifecycleObs := func(t *testing.T, runner *fakeTerminalSessionRunner, req ports.TerminalExecutionRequest, paneID string, term ports.ProcessTermination) ports.TerminalExecutionObservation {
		t.Helper()
		binding, ok := req.Process().ProviderPacketBinding()
		if !ok {
			t.Fatal("missing packet binding")
		}
		promptBytes, err := os.ReadFile(req.PromptFilePath().String())
		if err != nil {
			t.Fatal(err)
		}
		promptSum := sha256.Sum256(promptBytes)
		promptID, err := ports.NewProviderPacketIdentity(len(promptBytes), hex.EncodeToString(promptSum[:]))
		if err != nil {
			t.Fatal(err)
		}
		packetID, err := ports.NewProviderPacketIdentity(len(binding.Packet().Bytes()), testStdinDigest(binding.Packet().Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		transport, err := ports.NewTerminalProviderPacketTransportReceipt(packetID, promptID, promptID)
		if err != nil {
			t.Fatal(err)
		}
		stdinReceipt, err := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		var procObs ports.ProcessObservation
		switch term {
		case ports.ProcessTerminationStartSecurity,
			ports.ProcessTerminationStartConfiguration,
			ports.ProcessTerminationStartUnavailable,
			ports.ProcessTerminationStartFailed:
			procObs, err = ports.NewProcessObservation(nil, nil, nil, term, stdinReceipt, now, now)
		default:
			procObs, err = ports.NewProviderProcessObservation(nil, nil, nil, term, stdinReceipt, transport, now, now)
		}
		if err != nil {
			t.Fatal(err)
		}
		return func() ports.TerminalExecutionObservation {
			obs, obsErr := ports.NewTerminalExecutionObservation(ports.TerminalExecutionObservationInput{
				Process:         procObs,
				RuntimeIdentity: runner.identity,
				PaneID:          paneID,
			})
			if obsErr != nil {
				t.Fatal(obsErr)
			}
			return obs
		}()
	}

	preStartCases := []struct {
		name       string
		term       ports.ProcessTermination
		wantStatus ports.ProviderExecutionStatus
		wantCause  domain.RuntimeDiagnosticCause
		wantCancel bool
	}{
		{"pre-start cancelled", ports.ProcessTerminationCancelled, ports.ProviderExecutionStatusCancelled, domain.DiagnosticCauseProviderExecutionFailed, true},
		{"pre-start timed out", ports.ProcessTerminationTimedOut, ports.ProviderExecutionStatusTimedOut, domain.DiagnosticCauseTimedOut, false},
		{"pre-start security", ports.ProcessTerminationStartSecurity, ports.ProviderExecutionStatusSecurityViolation, domain.DiagnosticCauseProviderSpawnFailed, false},
		{"pre-start configuration", ports.ProcessTerminationStartConfiguration, ports.ProviderExecutionStatusConfigurationViolation, domain.DiagnosticCauseProviderSpawnFailed, false},
		{"pre-start unavailable", ports.ProcessTerminationStartUnavailable, ports.ProviderExecutionStatusUnavailable, domain.DiagnosticCauseProviderSpawnFailed, false},
		{"pre-start failed", ports.ProcessTerminationStartFailed, ports.ProviderExecutionStatusInternalFailure, domain.DiagnosticCauseProviderSpawnFailed, false},
	}
	for _, tc := range preStartCases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newTerminalTestFixture(t)
			runner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
			runner.runFunc = func(_ context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
				return buildNoLifecycleObs(t, runner, req, "", tc.term), nil
			}
			_, err := executeTerminalInvocation(context.Background(), runner, grokTerminalProfile{}, fx.baseRequest(t, terminalPurposeReview, []byte("prompt")))
			var df *terminalDriverFailure
			if !errors.As(err, &df) {
				t.Fatalf("error = %T (%v), want *terminalDriverFailure", err, err)
			}
			if df.Status() != tc.wantStatus || df.Cause() != tc.wantCause || df.CleanupCause() != "" {
				t.Fatalf("got status=%q cause=%q cleanup=%q, want %q / %q / \"\"", df.Status(), df.Cause(), df.CleanupCause(), tc.wantStatus, tc.wantCause)
			}
			if tc.wantCancel && !errors.Is(err, context.Canceled) {
				t.Fatalf("expected context.Canceled wrap, got %v", err)
			}
		})
	}

	for _, term := range []ports.ProcessTermination{
		ports.ProcessTerminationCancelled,
		ports.ProcessTerminationTimedOut,
		ports.ProcessTerminationResidualProcessGroup,
	} {
		t.Run("started pane without ProcessGroupAbsent fails closed ("+string(term)+")", func(t *testing.T) {
			fx := newTerminalTestFixture(t)
			runner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
			runner.runFunc = func(_ context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
				return buildNoLifecycleObs(t, runner, req, "pane-started-no-esrch", term), nil
			}
			_, err := executeTerminalInvocation(context.Background(), runner, grokTerminalProfile{}, fx.baseRequest(t, terminalPurposeReview, []byte("prompt")))
			var df *terminalDriverFailure
			if !errors.As(err, &df) {
				t.Fatalf("error = %T (%v), want *terminalDriverFailure", err, err)
			}
			if df.Status() != ports.ProviderExecutionStatusSecurityViolation ||
				df.Cause() != domain.DiagnosticCauseProcessGroupCleanupFailed ||
				df.CleanupCause() != domain.DiagnosticCauseProcessGroupCleanupFailed {
				t.Fatalf("started pane without ESRCH = status:%q cause:%q cleanup:%q, want security_violation / process_group_cleanup_failed",
					df.Status(), df.Cause(), df.CleanupCause())
			}
		})
	}

	for _, tc := range []struct {
		name       string
		term       ports.ProcessTermination
		wantStatus ports.ProviderExecutionStatus
		wantDiag   string
		wantCause  domain.RuntimeDiagnosticCause
		wantCancel bool
	}{
		{"started pane cancelled with ProcessGroupAbsent", ports.ProcessTerminationCancelled, ports.ProviderExecutionStatusCancelled, "process_cancelled", domain.DiagnosticCauseProviderExecutionFailed, true},
		{"started pane timed out with ProcessGroupAbsent", ports.ProcessTerminationTimedOut, ports.ProviderExecutionStatusTimedOut, "process_timeout", domain.DiagnosticCauseTimedOut, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newTerminalTestFixture(t)
			runner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
			runner.runFunc = func(_ context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
				return makeTerminalSessionObservation(t, runner, req, ports.TerminalExecutionObservationInput{
					PaneID: "pane-started-clean-esrch",
				}, tc.term, 0, true, nil, nil), nil
			}
			_, err := executeTerminalInvocation(context.Background(), runner, grokTerminalProfile{}, fx.baseRequest(t, terminalPurposeReview, []byte("prompt")))
			var df *terminalDriverFailure
			if !errors.As(err, &df) {
				t.Fatalf("error = %T (%v), want *terminalDriverFailure", err, err)
			}
			if df.Status() != tc.wantStatus || df.Diagnostic() != tc.wantDiag || df.Cause() != tc.wantCause || df.CleanupCause() != "" {
				t.Fatalf("got status=%q diag=%q cause=%q cleanup=%q, want %q / %q / %q / \"\"",
					df.Status(), df.Diagnostic(), df.Cause(), df.CleanupCause(), tc.wantStatus, tc.wantDiag, tc.wantCause)
			}
			if tc.wantCancel && !errors.Is(err, context.Canceled) {
				t.Fatalf("expected context.Canceled wrap, got %v", err)
			}
		})
	}

	for _, tc := range []struct {
		name     string
		term     ports.ProcessTermination
		exitCode *int
		signal   bool
		stageOut bool
	}{
		{"no-lifecycle exited zero with valid staged output still fails closed", ports.ProcessTerminationExited, func() *int { v := 0; return &v }(), false, true},
		{"no-lifecycle signaled still fails closed", ports.ProcessTerminationSignaled, nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newTerminalTestFixture(t)
			runner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
			runner.runFunc = func(_ context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
				if tc.stageOut {
					nonce := extractPromptNonce(t, req.PromptFilePath().String())
					outPath := findStagedOutputPath(t, fx.namespaceRoot, stagedOutputFilename)
					if err := os.WriteFile(outPath, []byte("# Must not be read\n"+terminalCompletionNoncePrefix+nonce+"\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				binding, _ := req.Process().ProviderPacketBinding()
				promptBytes, err := os.ReadFile(req.PromptFilePath().String())
				if err != nil {
					t.Fatal(err)
				}
				promptSum := sha256.Sum256(promptBytes)
				promptID, err := ports.NewProviderPacketIdentity(len(promptBytes), hex.EncodeToString(promptSum[:]))
				if err != nil {
					t.Fatal(err)
				}
				packetID, err := ports.NewProviderPacketIdentity(len(binding.Packet().Bytes()), testStdinDigest(binding.Packet().Bytes()))
				if err != nil {
					t.Fatal(err)
				}
				transport, err := ports.NewTerminalProviderPacketTransportReceipt(packetID, promptID, promptID)
				if err != nil {
					t.Fatal(err)
				}
				stdinReceipt, err := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
				if err != nil {
					t.Fatal(err)
				}
				var signals []ports.ProcessSignal
				if tc.signal {
					sig, sigErr := ports.NewProcessSignal(15, "SIGTERM")
					if sigErr != nil {
						t.Fatal(sigErr)
					}
					signals = []ports.ProcessSignal{sig}
				}
				now := time.Now().UTC()
				procObs, err := ports.NewProviderProcessObservation(nil, nil, tc.exitCode, tc.term, stdinReceipt, transport, now, now, signals...)
				if err != nil {
					t.Fatal(err)
				}
				input := ports.TerminalExecutionObservationInput{
					Process:         procObs,
					RuntimeIdentity: runner.identity,
					PaneID:          "pane-no-lifecycle",
				}
				if tc.stageOut {
					input.Reported = true
					input.ProgramStatus = ports.TerminalProgramStatusDone
					input.TurnCount = 1
				}
				return ports.NewTerminalExecutionObservation(input)
			}
			res, err := executeTerminalInvocation(context.Background(), runner, grokTerminalProfile{}, fx.baseRequest(t, terminalPurposeReview, []byte("prompt")))
			var df *terminalDriverFailure
			if !errors.As(err, &df) {
				t.Fatalf("error = %T (%v), want *terminalDriverFailure", err, err)
			}
			if df.Status() != ports.ProviderExecutionStatusSecurityViolation ||
				df.Cause() != domain.DiagnosticCauseProcessGroupCleanupFailed ||
				df.CleanupCause() != domain.DiagnosticCauseProcessGroupCleanupFailed {
				t.Fatalf("no-lifecycle %s = status:%q cause:%q cleanup:%q, want security_violation / process_group_cleanup_failed",
					tc.term, df.Status(), df.Cause(), df.CleanupCause())
			}
			if len(res.OutputBytes) != 0 {
				t.Fatalf("staged output was read despite !ProcessGroupAbsent(): %q", res.OutputBytes)
			}
		})
	}
}
