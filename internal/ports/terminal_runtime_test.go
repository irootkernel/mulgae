package ports

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestTerminalStatusAndBlockedKindEnums(t *testing.T) {
	t.Parallel()

	for _, status := range []TerminalProgramStatus{
		TerminalProgramStatusIdle,
		TerminalProgramStatusWorking,
		TerminalProgramStatusDone,
		TerminalProgramStatusBlocked,
		TerminalProgramStatusError,
	} {
		if !status.Valid() {
			t.Fatalf("TerminalProgramStatus(%q).Valid() = false, want true", status)
		}
	}
	for _, invalid := range []TerminalProgramStatus{"", "running", "IDLE", "done\n"} {
		if invalid.Valid() {
			t.Fatalf("TerminalProgramStatus(%q).Valid() = true, want false", invalid)
		}
	}

	for _, kind := range []TerminalBlockedKind{
		TerminalBlockedKindAuth,
		TerminalBlockedKindQuota,
		TerminalBlockedKindRateLimit,
		TerminalBlockedKindApproval,
		TerminalBlockedKindPermission,
		TerminalBlockedKindInput,
		TerminalBlockedKindUnknown,
	} {
		if !kind.Valid() {
			t.Fatalf("TerminalBlockedKind(%q).Valid() = false, want true", kind)
		}
	}
	for _, invalid := range []TerminalBlockedKind{"", "AUTH", "other", "auth\x00"} {
		if invalid.Valid() {
			t.Fatalf("TerminalBlockedKind(%q).Valid() = true, want false", invalid)
		}
	}
}

func TestTerminalPaneIDValidationAndPassthroughMarker(t *testing.T) {
	t.Parallel()

	for _, valid := range []string{"0", "t_019f596a", "pane-123:abc.def", strings.Repeat("a", 128)} {
		if !ValidTerminalPaneID(valid) {
			t.Fatalf("ValidTerminalPaneID(%q) = false, want true", valid)
		}
	}
	for _, invalid := range []string{
		"", "-leading-dash", "_leading-underscore", ".leading-dot",
		"has space", "has/slash", "has=eq", "has;semi", "has\nnewline", "has\x00nul",
		strings.Repeat("a", 129),
	} {
		if ValidTerminalPaneID(invalid) {
			t.Fatalf("ValidTerminalPaneID(%q) = true, want false", invalid)
		}
	}

	termVar, err := NewEnvironmentVariable("TERM", "xterm-256color")
	if err != nil {
		t.Fatal(err)
	}
	langVar, err := NewEnvironmentVariable("LANG", "en_US.UTF-8")
	if err != nil {
		t.Fatal(err)
	}
	marked, err := TerminalEnvironmentWithPassthroughMarker([]EnvironmentVariable{termVar, langVar})
	if err != nil {
		t.Fatalf("TerminalEnvironmentWithPassthroughMarker() error = %v", err)
	}
	if len(marked) != 3 ||
		marked[0].Name() != TerminalPaneIDEnvName || marked[0].Value() != TerminalPaneIDPassthroughDomainMarker ||
		marked[1].Name() != "LANG" || marked[2].Name() != "TERM" {
		t.Fatalf("marked environment = %#v", marked)
	}

	explicitID, err := NewEnvironmentVariable(TerminalPaneIDEnvName, "pane-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TerminalEnvironmentWithPassthroughMarker([]EnvironmentVariable{termVar, explicitID}); err == nil {
		t.Fatal("TerminalEnvironmentWithPassthroughMarker accepted explicit HC_TERMINAL_ID")
	}
	if _, err := TerminalEnvironmentWithPassthroughMarker([]EnvironmentVariable{termVar, termVar}); err == nil {
		t.Fatal("TerminalEnvironmentWithPassthroughMarker accepted duplicate variable")
	}
}

func TestSignalNameFromNumberUsesPlatformNames(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		num  int
		want string
	}{
		{1, "SIGHUP"},
		{2, "SIGINT"},
		{9, "SIGKILL"},
		{15, "SIGTERM"},
	} {
		sig, err := NewProcessSignalFromNumber(tc.num)
		if err != nil {
			t.Fatalf("NewProcessSignalFromNumber(%d): %v", tc.num, err)
		}
		if sig.Number() != tc.num || sig.Name() != tc.want || !sig.Valid() {
			t.Fatalf("signal = (%d, %q, valid=%t), want (%d, %q)", sig.Number(), sig.Name(), sig.Valid(), tc.num, tc.want)
		}
	}
	if _, err := NewProcessSignalFromNumber(0); err == nil {
		t.Fatal("NewProcessSignalFromNumber(0) accepted non-positive signal")
	}
	if _, err := NewProcessSignalFromNumber(-1); err == nil {
		t.Fatal("NewProcessSignalFromNumber(-1) accepted negative signal")
	}
}

func TestTerminalSignalRequestReasonsAndValid(t *testing.T) {
	t.Parallel()

	for _, reason := range []ProcessGroupSignalRequestReason{
		ProcessGroupSignalRequestPostOutput,
		ProcessGroupSignalRequestPostOutputEscalation,
		ProcessGroupSignalRequestCancellation,
		ProcessGroupSignalRequestTimeout,
		ProcessGroupSignalRequestStdinIncomplete,
		ProcessGroupSignalRequestResidualGroup,
		ProcessGroupSignalRequestInternalTeardown,
		ProcessGroupSignalRequestConversationTeardown,
		ProcessGroupSignalRequestConversationTeardownEscalation,
		ProcessGroupSignalRequestTerminalTeardown,
		ProcessGroupSignalRequestTerminalTeardownEscalation,
	} {
		if !reason.Valid() {
			t.Fatalf("reason %q should be valid", reason)
		}
	}
	if ProcessGroupSignalRequestReason("unknown").Valid() {
		t.Fatal("unknown reason reported valid")
	}

	for _, reason := range []ProcessGroupSignalRequestReason{
		ProcessGroupSignalRequestTerminalTeardown,
		ProcessGroupSignalRequestTerminalTeardownEscalation,
	} {
		signal, err := NewProcessSignalFromNumber(15)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := NewAcceptedProcessGroupSignalRequestReceipt(reason, signal)
		if err != nil || !receipt.Valid() {
			t.Fatalf("NewAcceptedProcessGroupSignalRequestReceipt(%q) = (%#v, %v)", reason, receipt, err)
		}
	}
}

func TestTerminalPacketBindingRequestAndTransportReceipt(t *testing.T) {
	t.Parallel()

	packet := schedulingTestPacket(t, []byte("terminal review prompt"))
	if !ProviderPacketChannelTerminal.Valid() {
		t.Fatal("ProviderPacketChannelTerminal is invalid")
	}
	binding, err := NewTerminalProviderPacketBinding(packet)
	if err != nil || !binding.Valid() || binding.Channel() != ProviderPacketChannelTerminal {
		t.Fatalf("NewTerminalProviderPacketBinding() = (%#v, %v)", binding, err)
	}
	if _, err := NewTerminalProviderPacketBinding(ProviderPacket{}); err == nil {
		t.Fatal("NewTerminalProviderPacketBinding accepted invalid packet")
	}

	req, err := NewProviderTerminalProcessRequest("/usr/bin/grok", []string{"/usr/bin/grok", "--no-leader"}, nil, "/neutral", binding, time.Minute)
	if err != nil || !req.Valid() || len(req.Stdin()) != 0 {
		t.Fatalf("NewProviderTerminalProcessRequest() = (%#v, %v)", req, err)
	}
	if _, err := NewProviderTerminalProcessRequest("/usr/bin/grok", []string{"/usr/bin/grok", "terminal review prompt"}, nil, "/neutral", binding, time.Minute); err == nil {
		t.Fatal("NewProviderTerminalProcessRequest accepted packet literal in argv")
	}
	protocolBinding, err := NewProtocolProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewProviderTerminalProcessRequest("/usr/bin/grok", []string{"/usr/bin/grok"}, nil, "/neutral", protocolBinding, time.Minute); err == nil {
		t.Fatal("NewProviderTerminalProcessRequest accepted protocol binding")
	}

	// Terminal requests reject post-output lifecycle.
	postOut, err := NewBoundedPostOutputLifecycle(ProcessOutputFramingStrictJSON, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewProviderProcessRequestWithPostOutputLifecycle("/usr/bin/grok", []string{"/usr/bin/grok"}, nil, "/neutral", binding, postOut, time.Minute); err == nil {
		t.Fatal("NewProviderProcessRequestWithPostOutputLifecycle accepted terminal binding")
	}

	// Terminal transport receipt requires matching valid pre-start & post-teardown
	// prompt-file digests with byte length >= packet byte length and zero native paths.
	promptWithNonce := schedulingTestPacket(t, []byte("terminal review prompt\n\nNONCE=abc123"))
	shorterPrompt := schedulingTestPacket(t, []byte("short"))
	otherSameLen := schedulingTestPacket(t, []byte("terminal review OTHER!"))

	exactReceipt, err := NewTerminalProviderPacketTransportReceipt(packet.Identity(), packet.Identity(), packet.Identity())
	if err != nil || !exactReceipt.Valid() {
		t.Fatalf("exact terminal transport receipt = (%#v, %v)", exactReceipt, err)
	}
	nonceReceipt, err := NewTerminalProviderPacketTransportReceipt(packet.Identity(), promptWithNonce.Identity(), promptWithNonce.Identity())
	if err != nil || !nonceReceipt.Valid() {
		t.Fatalf("nonce-appended terminal transport receipt = (%#v, %v)", nonceReceipt, err)
	}
	for _, tc := range []struct {
		name      string
		ref, cwd  string
		pre, post ProviderPacketIdentity
	}{
		{"missing pre/post", "", "", ProviderPacketIdentity{}, ProviderPacketIdentity{}},
		{"missing post", "", "", packet.Identity(), ProviderPacketIdentity{}},
		{"mismatched pre/post", "", "", packet.Identity(), otherSameLen.Identity()},
		{"same length different digest substitution", "", "", otherSameLen.Identity(), otherSameLen.Identity()},
		{"prompt shorter than packet", "", "", shorterPrompt.Identity(), shorterPrompt.Identity()},
		{"non-empty prompt ref", "@prompt.md", "", packet.Identity(), packet.Identity()},
		{"non-empty snapshot cwd", "", "/work", packet.Identity(), packet.Identity()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewProviderPacketTransportReceipt(ProviderPacketChannelTerminal, packet.Identity(), tc.ref, tc.cwd, tc.pre, tc.post); err == nil {
				t.Fatalf("invalid terminal transport receipt accepted for %s", tc.name)
			}
		})
	}

	emptyStdin, err := NewStdinWriteReceipt(0, 0, schedulingStdinWriteSHA256(nil), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProviderPacketTransportReceipt(ProcessTerminationExited, emptyStdin, nonceReceipt); err != nil {
		t.Fatalf("valid terminal transport receipt rejected: %v", err)
	}
	nonEmptyStdin, err := NewStdinWriteReceipt(5, 5, schedulingStdinWriteSHA256([]byte("hello")), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProviderPacketTransportReceipt(ProcessTerminationExited, nonEmptyStdin, nonceReceipt); err == nil {
		t.Fatal("terminal transport receipt accepted non-empty stdin receipt")
	}
	for _, startFail := range []ProcessTermination{
		ProcessTerminationStartFailed,
		ProcessTerminationStartUnavailable,
		ProcessTerminationStartConfiguration,
		ProcessTerminationStartSecurity,
	} {
		if err := validateProviderPacketTransportReceipt(startFail, emptyStdin, nonceReceipt); err == nil {
			t.Fatalf("terminal transport receipt accepted start failure %q", startFail)
		}
	}
}

func TestTerminalRuntimeIdentityPaneLaunchAndSessionTypes(t *testing.T) {
	t.Parallel()

	digest := "sha256:" + strings.Repeat("a", 64)
	identity, err := NewTerminalRuntimeIdentity("/opt/homebrew/bin/hc", digest, "0.1.20", 1)
	if err != nil || !identity.Valid() {
		t.Fatalf("NewTerminalRuntimeIdentity() = (%#v, %v)", identity, err)
	}
	if _, err := NewTerminalRuntimeIdentity("relative/hc", digest, "0.1.20", 1); err == nil {
		t.Fatal("accepted relative executable")
	}
	if _, err := NewTerminalRuntimeIdentity("/opt/homebrew/bin/hc", "bad", "0.1.20", 1); err == nil {
		t.Fatal("accepted invalid sha256")
	}
	if _, err := NewTerminalRuntimeIdentity("/opt/homebrew/bin/hc", digest, "", 1); err == nil {
		t.Fatal("accepted empty version")
	}
	if _, err := NewTerminalRuntimeIdentity("/opt/homebrew/bin/hc", digest, "0.1.20", 0); err == nil {
		t.Fatal("accepted non-positive generation")
	}

	source, _ := NewAnchoredRoot("/private/source")
	inputRoot, _ := NewAnchoredRoot("/private/tmp/ns/scratch/input")
	promptPath, _ := NewAnchoredRoot("/private/tmp/ns/scratch/input/pane1/prompt.md")
	cred, _ := NewAnchoredRoot("/Users/alice/.grok")
	writable, _ := NewAnchoredRoot("/private/tmp/ns")
	nativeHome, _ := NewAnchoredRoot("/Users/alice")
	sessionDir, _ := NewAnchoredRoot("/private/tmp/mgh-501/0123456789abcdef")
	paneCtrlDir, _ := NewAnchoredRoot("/private/tmp/mgh-501/0123456789abcdef/panes/p1")
	outsideCtrlDir, _ := NewAnchoredRoot("/private/tmp/other/panes/p1")

	boundary, err := NewLiveReadOnlyBoundary([]AnchoredRoot{source, inputRoot}, []AnchoredRoot{cred}, writable)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err = NewLiveReadOnlyBoundaryWithControlPlane(boundary, []AnchoredRoot{sessionDir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	paneBoundary, err := NewLiveReadOnlyBoundaryWithPaneTTY(boundary, nativeHome)
	if err != nil {
		t.Fatal(err)
	}

	packet := schedulingTestPacket(t, []byte("review this code"))
	binding, err := NewTerminalProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	baseReq, err := NewProviderTerminalProcessRequest("/usr/local/bin/grok", []string{"/usr/local/bin/grok"}, nil, "/Users/alice/.mulgae/home", binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Guarded terminal request must require PaneTTY.
	if _, err := NewLiveReadOnlyProcessRequest(baseReq, boundary); err == nil {
		t.Fatal("guarded terminal request accepted non-PaneTTY boundary")
	}
	guardedReq, err := NewLiveReadOnlyProcessRequest(baseReq, paneBoundary)
	if err != nil {
		t.Fatalf("NewLiveReadOnlyProcessRequest(terminal + PaneTTY): %v", err)
	}
	// Protocol request must reject PaneTTY boundary.
	protoBinding, _ := NewProtocolProviderPacketBinding(packet)
	protoReq, _ := NewProviderProtocolProcessRequest("/usr/local/bin/grok", []string{"/usr/local/bin/grok"}, nil, "/Users/alice/.mulgae/home", protoBinding, time.Minute)
	if _, err := NewLiveReadOnlyProcessRequest(protoReq, paneBoundary); err == nil {
		t.Fatal("protocol request accepted PaneTTY boundary")
	}

	launchReq, err := NewPaneLaunchRequest(guardedReq, paneCtrlDir)
	if err != nil || !launchReq.Valid() {
		t.Fatalf("NewPaneLaunchRequest() = (%#v, %v)", launchReq, err)
	}
	if _, err := NewPaneLaunchRequest(guardedReq, outsideCtrlDir); err == nil {
		t.Fatal("NewPaneLaunchRequest accepted control dir outside ControlPlaneRoots")
	}

	spec, err := NewPaneLaunchSpec(
		"/usr/local/bin/mulgae",
		[]string{"/usr/local/bin/mulgae", "__mulgae_paneexec_v1", "arg"},
		paneCtrlDir.String()+"/env.json", digest,
		paneCtrlDir.String()+"/seatbelt.sb", digest,
	)
	if err != nil || !spec.Valid() {
		t.Fatalf("NewPaneLaunchSpec() = (%#v, %v)", spec, err)
	}
	argvCopy := spec.Argv()
	argvCopy[0] = "mutated"
	if spec.Argv()[0] != "/usr/local/bin/mulgae" {
		t.Fatal("PaneLaunchSpec.Argv() exposed mutable backing slice")
	}

	if _, err := NewPaneLaunchSpec(
		"/usr/local/bin/mulgae",
		[]string{"/usr/local/bin/mulgae", ""},
		paneCtrlDir.String()+"/env.json", digest,
		paneCtrlDir.String()+"/seatbelt.sb", digest,
	); err == nil {
		t.Fatal("NewPaneLaunchSpec accepted empty trampoline mode argv[1]")
	}

	labels := map[string]string{"mulgae_registry": "gen-1"}
	termReq, err := NewTerminalExecutionRequest(TerminalExecutionRequestInput{
		Process:             guardedReq,
		StartupTimeout:      15 * time.Second,
		PromptFilePath:      promptPath,
		InitialInput:        "Read prompt.md and write output",
		RequireOSCReporting: true,
		CheckInInterval:     5 * time.Second,
		Columns:             120,
		Rows:                40,
		Labels:              labels,
	})
	if err != nil || !termReq.Valid() {
		t.Fatalf("NewTerminalExecutionRequest() = (%#v, %v)", termReq, err)
	}
	labels["mulgae_registry"] = "mutated"
	if termReq.Labels()["mulgae_registry"] != "gen-1" {
		t.Fatal("TerminalExecutionRequest did not clone labels")
	}
	if _, err := NewTerminalExecutionRequest(TerminalExecutionRequestInput{
		Process:        guardedReq,
		StartupTimeout: time.Minute, // must be strictly < Process.Timeout()
		PromptFilePath: promptPath,
	}); err == nil {
		t.Fatal("TerminalExecutionRequest accepted startupTimeout == process timeout")
	}
	outsidePrompt, _ := NewAnchoredRoot("/private/tmp/other/prompt.md")
	if _, err := NewTerminalExecutionRequest(TerminalExecutionRequestInput{
		Process:        guardedReq,
		StartupTimeout: 10 * time.Second,
		PromptFilePath: outsidePrompt,
	}); err == nil {
		t.Fatal("TerminalExecutionRequest accepted prompt file outside ReadOnlyRoots")
	}
	// Prompt file whose directory itself is not under ReadOnlyRoots (only leaf path matched) must be rejected.
	leafOnlyPrompt := inputRoot
	if _, err := NewTerminalExecutionRequest(TerminalExecutionRequestInput{
		Process:        guardedReq,
		StartupTimeout: 10 * time.Second,
		PromptFilePath: leafOnlyPrompt,
	}); err == nil {
		t.Fatal("TerminalExecutionRequest accepted prompt file whose parent dir is outside ReadOnlyRoots")
	}
	// Mismatched zero/non-zero terminal dimensions must be rejected.
	if _, err := NewTerminalExecutionRequest(TerminalExecutionRequestInput{
		Process:        guardedReq,
		StartupTimeout: 10 * time.Second,
		PromptFilePath: promptPath,
		Columns:        120,
		Rows:           0,
	}); err == nil {
		t.Fatal("TerminalExecutionRequest accepted Columns > 0 with Rows == 0")
	}
	if _, err := NewTerminalExecutionRequest(TerminalExecutionRequestInput{
		Process:        guardedReq,
		StartupTimeout: 10 * time.Second,
		PromptFilePath: promptPath,
		Columns:        0,
		Rows:           40,
	}); err == nil {
		t.Fatal("TerminalExecutionRequest accepted Columns == 0 with Rows > 0")
	}

	proc := terminalTestProcess(t, newProviderExecutionTestInvocation(t), ProcessTerminationSignaled, true, ProcessGroupSignalRequestTerminalTeardown)
	screen := []byte("screen output")
	obs, err := NewTerminalExecutionObservation(TerminalExecutionObservationInput{
		Process:         proc,
		RuntimeIdentity: identity,
		ProgramStatus:   TerminalProgramStatusDone,
		Reported:        true,
		TurnCount:       1,
		ScreenCapture:   screen,
		PaneID:          "pane-1",
	})
	if err != nil || !obs.Valid() {
		t.Fatalf("NewTerminalExecutionObservation() = (%#v, %v)", obs, err)
	}
	screen[0] = 'X'
	if string(obs.ScreenCapture()) != "screen output" {
		t.Fatal("TerminalExecutionObservation exposed mutable screen capture")
	}
	if _, err := NewTerminalExecutionObservation(TerminalExecutionObservationInput{
		Process:         proc,
		RuntimeIdentity: identity,
		ProgramStatus:   TerminalProgramStatusDone,
		Reported:        true,
		BlockedKind:     TerminalBlockedKindAuth, // invalid when not blocked
	}); err == nil {
		t.Fatal("TerminalExecutionObservation accepted blocked kind with non-blocked status")
	}
	if _, err := NewTerminalExecutionObservation(TerminalExecutionObservationInput{
		Process:         proc,
		RuntimeIdentity: identity,
		ProgramStatus:   TerminalProgramStatusDone,
		Reported:        false, // ProgramStatus requires Reported == true
	}); err == nil {
		t.Fatal("TerminalExecutionObservation accepted ProgramStatus with Reported == false")
	}
	if _, err := NewTerminalExecutionObservation(TerminalExecutionObservationInput{
		Process:         proc,
		RuntimeIdentity: identity,
		Reported:        false,
		TurnCount:       1, // TurnCount > 0 requires Reported == true
	}); err == nil {
		t.Fatal("TerminalExecutionObservation accepted TurnCount > 0 with Reported == false")
	}
	if _, err := NewTerminalExecutionObservation(TerminalExecutionObservationInput{
		Process:            proc,
		RuntimeIdentity:    identity,
		Reported:           true,
		ExitedBeforeReport: true,
	}); err == nil {
		t.Fatal("TerminalExecutionObservation accepted reported && exitedBeforeReport")
	}
	// Start failure without transport receipt is allowed when unreported, but MUST fail when Reported/ProgramStatus/TurnCount is set.
	emptyStdin, err := NewStdinWriteReceipt(0, 0, providerTestDigest(nil), true)
	if err != nil {
		t.Fatal(err)
	}
	startFailProc, err := NewProcessObservation(nil, nil, nil, ProcessTerminationStartFailed, emptyStdin, providerExecutionTestStartedAt, providerExecutionTestEndedAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewTerminalExecutionObservation(TerminalExecutionObservationInput{
		Process:            startFailProc,
		RuntimeIdentity:    identity,
		ExitedBeforeReport: true,
	}); err != nil {
		t.Fatalf("unreported start failure terminal observation rejected: %v", err)
	}
	if _, err := NewTerminalExecutionObservation(TerminalExecutionObservationInput{
		Process:         startFailProc,
		RuntimeIdentity: identity,
		Reported:        true,
	}); err == nil {
		t.Fatal("TerminalExecutionObservation accepted Reported == true without terminal transport receipt")
	}

	// Interface compile check.
	var _ PaneLaunchBuilder = terminalTestLaunchBuilder{}
	var _ TerminalSessionRunner = terminalTestSessionRunner{}
}

type terminalTestLaunchBuilder struct{}

func (terminalTestLaunchBuilder) BuildPaneLaunch(context.Context, PaneLaunchRequest) (PaneLaunchSpec, error) {
	return PaneLaunchSpec{}, nil
}

type terminalTestSessionRunner struct{}

func (terminalTestSessionRunner) RunTerminal(context.Context, TerminalExecutionRequest) (TerminalExecutionObservation, error) {
	return TerminalExecutionObservation{}, nil
}
func (terminalTestSessionRunner) DrainLabeledPanes(context.Context, string, string) error { return nil }
func (terminalTestSessionRunner) RuntimeIdentity(context.Context) (TerminalRuntimeIdentity, error) {
	return TerminalRuntimeIdentity{}, nil
}
func (terminalTestSessionRunner) Close(context.Context) error { return nil }

func terminalTestProcess(
	t *testing.T,
	invocation ProviderInvocation,
	termination ProcessTermination,
	withLifecycle bool,
	requestReasons ...ProcessGroupSignalRequestReason,
) ProcessObservation {
	t.Helper()
	packetIdentity := invocation.InputIdentity()
	transport, err := NewTerminalProviderPacketTransportReceipt(packetIdentity, packetIdentity, packetIdentity)
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := NewStdinWriteReceipt(0, 0, providerTestDigest(nil), true)
	if err != nil {
		t.Fatal(err)
	}
	if !withLifecycle {
		var exitCode *int
		var signals []ProcessSignal
		switch termination {
		case ProcessTerminationExited:
			code := 0
			exitCode = &code
		case ProcessTerminationSignaled:
			sig, err := NewProcessSignalFromNumber(15)
			if err != nil {
				t.Fatal(err)
			}
			signals = []ProcessSignal{sig}
		}
		proc, err := NewProviderProcessObservation(
			[]byte("terminal screen"), nil, exitCode, termination, stdin, transport,
			providerExecutionTestStartedAt, providerExecutionTestEndedAt, signals...,
		)
		if err != nil {
			t.Fatal(err)
		}
		return proc
	}
	requests := make([]ProcessGroupSignalRequestReceipt, 0, len(requestReasons))
	for _, reason := range requestReasons {
		sigNum := 15
		if reason == ProcessGroupSignalRequestTerminalTeardownEscalation {
			sigNum = 9
		}
		sig, err := NewProcessSignalFromNumber(sigNum)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := NewAcceptedProcessGroupSignalRequestReceipt(reason, sig)
		if err != nil {
			t.Fatal(err)
		}
		requests = append(requests, receipt)
	}
	var final ProcessFinalTermination
	switch termination {
	case ProcessTerminationExited:
		code := 0
		if len(requestReasons) > 0 {
			code = 143
		}
		final, err = NewExitedProcessFinalTermination(code)
	default:
		sig, sigErr := NewProcessSignalFromNumber(15)
		if sigErr != nil {
			t.Fatal(sigErr)
		}
		final, err = NewSignaledProcessFinalTermination(sig)
	}
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := NewProcessLifecycleReceipt(final, true, requests)
	if err != nil {
		t.Fatal(err)
	}
	proc, err := NewStartedProviderProcessObservation(
		[]byte("terminal screen"), nil, termination, stdin, transport, lifecycle,
		providerExecutionTestStartedAt, providerExecutionTestEndedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	return proc
}

func TestTerminalSessionCompletedTruthfulInvariants(t *testing.T) {
	t.Parallel()

	invocation := newProviderExecutionTestInvocation(t)

	// 1. Intentional terminal teardown (SIGTERM) with ProcessGroupAbsent() == true -> true.
	teardown := terminalTestProcess(t, invocation, ProcessTerminationSignaled, true, ProcessGroupSignalRequestTerminalTeardown)
	if !teardown.TerminalSessionCompleted() || !teardown.ProcessGroupAbsent() {
		t.Fatal("signaled terminal teardown with absent group should be completed")
	}

	// 2. Escalated terminal teardown (SIGTERM -> SIGKILL) -> true.
	escalated := terminalTestProcess(t, invocation, ProcessTerminationSignaled, true,
		ProcessGroupSignalRequestTerminalTeardown, ProcessGroupSignalRequestTerminalTeardownEscalation)
	if !escalated.TerminalSessionCompleted() {
		t.Fatal("escalated terminal teardown should be completed")
	}

	// 3. Exited after terminal teardown (e.g. TUI caught SIGTERM and exited 143) -> true.
	caughtExit := terminalTestProcess(t, invocation, ProcessTerminationExited, true, ProcessGroupSignalRequestTerminalTeardown)
	if !caughtExit.TerminalSessionCompleted() {
		t.Fatal("exited after terminal teardown should be completed")
	}

	// 4. Natural exit 0 with ProcessGroupAbsent() == true and zero signals -> true.
	naturalZero := terminalTestProcess(t, invocation, ProcessTerminationExited, true)
	if !naturalZero.TerminalSessionCompleted() {
		t.Fatal("natural exit 0 with absent process group should be completed")
	}

	// 5. Missing ProcessGroupAbsent (no lifecycle receipt) -> false!
	noLifecycle := terminalTestProcess(t, invocation, ProcessTerminationExited, false)
	if noLifecycle.TerminalSessionCompleted() {
		t.Fatal("terminal process without lifecycle/ProcessGroupAbsent reported completed")
	}

	// 6. Non-zero natural exit with no teardown signals -> false!
	packetIdentity := invocation.InputIdentity()
	transport, _ := NewTerminalProviderPacketTransportReceipt(packetIdentity, packetIdentity, packetIdentity)
	stdin, _ := NewStdinWriteReceipt(0, 0, providerTestDigest(nil), true)
	nonZeroFinal, _ := NewExitedProcessFinalTermination(1)
	nonZeroLifecycle, _ := NewProcessLifecycleReceipt(nonZeroFinal, true, nil)
	nonZeroNatural, err := NewStartedProviderProcessObservation(
		[]byte("err"), nil, ProcessTerminationExited, stdin, transport, nonZeroLifecycle,
		providerExecutionTestStartedAt, providerExecutionTestEndedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if nonZeroNatural.TerminalSessionCompleted() {
		t.Fatal("natural non-zero exit without terminal teardown reported completed")
	}

	// 7. Unsolicited signal (no signal requests) -> false!
	unsolicitedSignal := terminalTestProcess(t, invocation, ProcessTerminationSignaled, true)
	if unsolicitedSignal.TerminalSessionCompleted() {
		t.Fatal("unsolicited signal reported TerminalSessionCompleted")
	}

	// 8. Wrong signal reasons (cancellation, timeout, conversation teardown) -> false!
	for _, reason := range []ProcessGroupSignalRequestReason{
		ProcessGroupSignalRequestCancellation,
		ProcessGroupSignalRequestTimeout,
		ProcessGroupSignalRequestInternalTeardown,
		ProcessGroupSignalRequestConversationTeardown,
	} {
		wrong := terminalTestProcess(t, invocation, ProcessTerminationSignaled, true, reason)
		if wrong.TerminalSessionCompleted() {
			t.Fatalf("signal reason %q falsely reported TerminalSessionCompleted", reason)
		}
		wrongExit := terminalTestProcess(t, invocation, ProcessTerminationExited, true, reason)
		if wrongExit.TerminalSessionCompleted() {
			t.Fatalf("exited with signal reason %q falsely reported TerminalSessionCompleted", reason)
		}
	}

	// 9. Unsolicited SIGSEGV after a SIGTERM teardown request MUST fail closed:
	// FinalTermination signal does not match any teardown signal request.
	sigterm, _ := NewProcessSignalFromNumber(15)
	sigsegv, _ := NewProcessSignalFromNumber(11)
	termReqReceipt, _ := NewAcceptedProcessGroupSignalRequestReceipt(ProcessGroupSignalRequestTerminalTeardown, sigterm)
	segvFinal, _ := NewSignaledProcessFinalTermination(sigsegv)
	segvLifecycle, _ := NewProcessLifecycleReceipt(segvFinal, true, []ProcessGroupSignalRequestReceipt{termReqReceipt})
	segvProc, err := NewStartedProviderProcessObservation(
		[]byte("crash"), nil, ProcessTerminationSignaled, stdin, transport, segvLifecycle,
		providerExecutionTestStartedAt, providerExecutionTestEndedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if segvProc.TerminalSessionCompleted() {
		t.Fatal("unsolicited SIGSEGV after SIGTERM teardown falsely reported TerminalSessionCompleted")
	}
	// SIGSEGV after SIGTERM teardown must be rejected for non-internal failure statuses and accepted only for internal_failure.
	if _, err := NewFailedProviderExecutionObservationWithCause(ProviderExecutionStatusUnavailable, invocation, segvProc, "provider_unavailable", domain.DiagnosticCauseProviderExecutionFailed, ""); err == nil {
		t.Fatal("unsolicited SIGSEGV after SIGTERM teardown accepted as unavailable")
	}
	if _, err := NewFailedProviderExecutionObservationWithCause(ProviderExecutionStatusAuthentication, invocation, segvProc, "provider_auth", domain.DiagnosticCauseAuthenticationFailed, ""); err == nil {
		t.Fatal("unsolicited SIGSEGV after SIGTERM teardown accepted as authentication")
	}
	if _, err := NewFailedProviderExecutionObservationWithCause(ProviderExecutionStatusInternalFailure, invocation, segvProc, "provider_signaled", domain.DiagnosticCauseProviderExecutionFailed, ""); err != nil {
		t.Fatalf("unsolicited SIGSEGV after SIGTERM teardown rejected as internal_failure: %v", err)
	}

	// 10. ProcessTerminationExited paired with a signaled FinalTermination must fail closed.
	termFinal, _ := NewSignaledProcessFinalTermination(sigterm)
	mismatchLifecycle, _ := NewProcessLifecycleReceipt(termFinal, true, []ProcessGroupSignalRequestReceipt{termReqReceipt})
	mismatchProc, err := NewStartedProviderProcessObservation(
		[]byte("mismatch"), nil, ProcessTerminationExited, stdin, transport, mismatchLifecycle,
		providerExecutionTestStartedAt, providerExecutionTestEndedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if mismatchProc.TerminalSessionCompleted() {
		t.Fatal("exited disposition with signaled FinalTermination falsely reported TerminalSessionCompleted")
	}

	// 11. Non-terminal transport (protocol) -> false!
	protoTeardown := conversationTeardownTestProcess(t, invocation, ProcessTerminationSignaled, ProcessGroupSignalRequestConversationTeardown)
	if protoTeardown.TerminalSessionCompleted() {
		t.Fatal("protocol observation falsely reported TerminalSessionCompleted")
	}
}

func TestProviderExecutionObservationTerminalChannelAllStatuses(t *testing.T) {
	t.Parallel()

	invocation := newProviderExecutionTestInvocation(t)
	resultBytes := []byte("# Terminal review report\n")
	result := newProviderExecutionTestResult(t, invocation, resultBytes)

	// 1. Succeeded: accepts isolated stdout result with TerminalSessionCompleted (teardown & natural zero exit).
	for _, tc := range []struct {
		name string
		proc ProcessObservation
		want bool
	}{
		{"terminal teardown signaled", terminalTestProcess(t, invocation, ProcessTerminationSignaled, true, ProcessGroupSignalRequestTerminalTeardown), true},
		{"terminal teardown escalated", terminalTestProcess(t, invocation, ProcessTerminationSignaled, true, ProcessGroupSignalRequestTerminalTeardown, ProcessGroupSignalRequestTerminalTeardownEscalation), true},
		{"terminal natural exit 0", terminalTestProcess(t, invocation, ProcessTerminationExited, true), true},
		{"terminal missing lifecycle/ProcessGroupAbsent", terminalTestProcess(t, invocation, ProcessTerminationExited, false), false},
		{"terminal unsolicited signal", terminalTestProcess(t, invocation, ProcessTerminationSignaled, true), false},
		{"terminal cancellation signal", terminalTestProcess(t, invocation, ProcessTerminationSignaled, true, ProcessGroupSignalRequestCancellation), false},
	} {
		t.Run("succeeded/"+tc.name, func(t *testing.T) {
			obs, err := NewIsolatedSuccessfulProviderExecutionObservation(invocation, result, tc.proc)
			if tc.want && (err != nil || !obs.Succeeded()) {
				t.Fatalf("succeeded terminal observation rejected: %v", err)
			}
			if !tc.want && err == nil {
				t.Fatalf("invalid succeeded terminal observation accepted for %s", tc.name)
			}
		})
	}

	// 2. Every failure status on a completed terminal teardown (e.g., live TUI torn down after blocked/error/staging failure).
	teardownProc := terminalTestProcess(t, invocation, ProcessTerminationSignaled, true, ProcessGroupSignalRequestTerminalTeardown)
	for _, tc := range []struct {
		status ProviderExecutionStatus
		code   string
		cause  domain.RuntimeDiagnosticCause
		allow  bool
	}{
		{ProviderExecutionStatusUnavailable, "provider_unavailable", domain.DiagnosticCauseProviderExecutionFailed, true},
		{ProviderExecutionStatusTimedOut, "provider_timeout", domain.DiagnosticCauseTimedOut, true},
		{ProviderExecutionStatusAuthentication, "provider_auth", domain.DiagnosticCauseAuthenticationFailed, true},
		{ProviderExecutionStatusQuota, "provider_quota", domain.DiagnosticCauseQuotaExceeded, true},
		{ProviderExecutionStatusRateLimit, "provider_rate_limit", domain.DiagnosticCauseRateLimited, true},
		{ProviderExecutionStatusSecurityViolation, "provider_security", domain.DiagnosticCausePermissionDenied, true},
		{ProviderExecutionStatusMutationViolation, "provider_mutation", domain.DiagnosticCauseWorkspaceRevalidationFailed, true},
		{ProviderExecutionStatusConfigurationViolation, "provider_config", domain.DiagnosticCauseProviderExecutionFailed, true},
		{ProviderExecutionStatusArtifactFailure, "provider_output_missing", domain.DiagnosticCauseProviderOutputFileMissing, true},
		{ProviderExecutionStatusInternalFailure, "provider_internal", domain.DiagnosticCauseProviderExecutionFailed, true},
		// Cancelled MUST NEVER match a completed terminal teardown; it requires ProcessTerminationCancelled.
		{ProviderExecutionStatusCancelled, "provider_cancelled", domain.DiagnosticCauseProviderExecutionFailed, false},
	} {
		t.Run("terminal_teardown_failure/"+string(tc.status), func(t *testing.T) {
			obs, err := NewFailedProviderExecutionObservationWithCause(tc.status, invocation, teardownProc, tc.code, tc.cause, "")
			if tc.allow && (err != nil || obs.Status() != tc.status) {
				t.Fatalf("status %q rejected on terminal teardown: %v", tc.status, err)
			}
			if !tc.allow && err == nil {
				t.Fatalf("status %q unexpectedly accepted on terminal teardown", tc.status)
			}
		})
	}

	// 3. Cancelled matches ProcessTerminationCancelled; TimedOut matches ProcessTerminationTimedOut;
	// SecurityViolation matches ProcessTerminationResidualProcessGroup.
	cancelledProc := terminalTestProcess(t, invocation, ProcessTerminationCancelled, true, ProcessGroupSignalRequestCancellation)
	if _, err := NewFailedProviderExecutionObservationWithCause(ProviderExecutionStatusCancelled, invocation, cancelledProc, "provider_cancelled", domain.DiagnosticCauseProviderExecutionFailed, ""); err != nil {
		t.Fatalf("cancelled terminal observation rejected: %v", err)
	}
	timedOutProc := terminalTestProcess(t, invocation, ProcessTerminationTimedOut, true, ProcessGroupSignalRequestTimeout)
	if _, err := NewFailedProviderExecutionObservationWithCause(ProviderExecutionStatusTimedOut, invocation, timedOutProc, "provider_timeout", domain.DiagnosticCauseTimedOut, ""); err != nil {
		t.Fatalf("timed-out terminal observation rejected: %v", err)
	}
	residualProc := terminalTestProcess(t, invocation, ProcessTerminationResidualProcessGroup, false)
	if _, err := NewFailedProviderExecutionObservationWithCause(ProviderExecutionStatusSecurityViolation, invocation, residualProc, "process_group_cleanup", domain.DiagnosticCauseProcessGroupCleanupFailed, ""); err != nil {
		t.Fatalf("residual-group terminal observation rejected: %v", err)
	}

	// 4. Unsolicited signal on terminal pane MUST fail closed as internal_failure only (never auth/unavailable/artifact/etc.).
	unsolicitedProc := terminalTestProcess(t, invocation, ProcessTerminationSignaled, true)
	if _, err := NewFailedProviderExecutionObservationWithCause(ProviderExecutionStatusInternalFailure, invocation, unsolicitedProc, "provider_signaled", domain.DiagnosticCauseProviderExecutionFailed, ""); err != nil {
		t.Fatalf("internal_failure on unsolicited signal rejected: %v", err)
	}
	for _, forbidden := range []ProviderExecutionStatus{
		ProviderExecutionStatusUnavailable,
		ProviderExecutionStatusTimedOut,
		ProviderExecutionStatusAuthentication,
		ProviderExecutionStatusQuota,
		ProviderExecutionStatusRateLimit,
		ProviderExecutionStatusMutationViolation,
		ProviderExecutionStatusConfigurationViolation,
		ProviderExecutionStatusArtifactFailure,
		ProviderExecutionStatusCancelled,
	} {
		t.Run("unsolicited_signal_rejects/"+string(forbidden), func(t *testing.T) {
			if _, err := NewFailedProviderExecutionObservationWithCause(forbidden, invocation, unsolicitedProc, "unexpected", domain.DiagnosticCauseProviderExecutionFailed, ""); err == nil {
				t.Fatalf("unsolicited signal accepted for %q", forbidden)
			}
		})
	}

	// 5. Protocol session observation must be rejected on terminal channel.
	session, err := NewProviderSessionObservation(ProviderSessionObservationInput{
		Phase:    ProviderSessionPhaseTurn,
		Terminal: ProviderSessionFailed,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewFailedProtocolProviderExecutionObservationWithCause(ProviderExecutionStatusUnavailable, invocation, teardownProc, session, "provider_unavailable", domain.DiagnosticCauseProviderExecutionFailed, ""); err == nil {
		t.Fatal("terminal process accepted protocol session observation")
	}
}
