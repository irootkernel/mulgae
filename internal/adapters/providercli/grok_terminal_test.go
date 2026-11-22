//go:build darwin && arm64

package providercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	gittargetadapter "github.com/irootkernel/mulgae/internal/adapters/gittarget"
	herdradapter "github.com/irootkernel/mulgae/internal/adapters/herdr"
	processadapter "github.com/irootkernel/mulgae/internal/adapters/process"
	runtimeadapter "github.com/irootkernel/mulgae/internal/adapters/runtime"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestGrokTerminalFlagsMinimalRequirementsAndDisposableHomes(t *testing.T) {
	fx := newTerminalTestFixture(t)
	profile := grokTerminalProfile{}
	def, err := NewRuntimeDefinition(FamilyGrok, "grok_flags", "1.0.89", "/private/bin/grok", "", "grok_flags", []string{"/private/bin/grok"}, nil, fx.neutralCWD.String(), 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	def.grokModel = "grok-4.7"
	def.grokReasoningEffort = "high"
	def.grokSettingsIdentity = grokSettingsIdentity(def.grokModel, def.grokReasoningEffort)

	inv := terminalProfileInvocation{
		Definition:    def,
		Purpose:       terminalPurposeReview,
		LiveScope:     domain.LiveSourceWorkspace,
		HasLiveScope:  true,
		NamespaceRoot: fx.namespaceRoot,
		ScratchDir:    filepath.Join(fx.namespaceRoot, "scratch"),
		HomeDir:       filepath.Join(fx.namespaceRoot, "home"),
		PromptPath:    filepath.Join(fx.namespaceRoot, "scratch", "input", "inv-1", "prompt.md"),
		OutputPath:    filepath.Join(fx.namespaceRoot, "scratch", "output", "inv-1", "role-report.md"),
		NeutralCWD:    fx.neutralCWD,
		NativeHome:    fx.nativeHome,
		SourceRoot:    fx.sourceRoot,
	}

	env, err := profile.PrepareDisposableHomes(inv)
	if err != nil {
		t.Fatal(err)
	}
	envMap := credentialSourceEnvironment(env)
	wantGrokHome := filepath.Join(fx.namespaceRoot, "home", ".grok")
	if envMap["GROK_HOME"] != wantGrokHome {
		t.Fatalf("GROK_HOME = %q, want %q", envMap["GROK_HOME"], wantGrokHome)
	}
	reqPath := filepath.Join(wantGrokHome, "requirements.toml")
	reqBytes, err := os.ReadFile(reqPath)
	if err != nil {
		t.Fatalf("read disposable requirements.toml: %v", err)
	}
	if string(reqBytes) != grokMinimalDisposableRequirementsTOML {
		t.Fatalf("disposable requirements.toml drifted")
	}
	if strings.Contains(string(reqBytes), "repo_status_in_system_prompt") {
		t.Fatalf("minimal disposable requirements.toml retained unknown Grok 1.0.89 field repo_status_in_system_prompt: %s", reqBytes)
	}
	wantSections := map[string]map[string]string{
		"": {
			"fail_closed":                    "true",
			"allow_managed_mcp_servers_only": "true",
			"enable_all_project_mcp_servers": "false",
			"allowed_mcp_servers":            "[]",
			"plugin_auto_update":             "false",
		},
		"compat.claude": {
			"agents": "false",
			"hooks":  "false",
			"mcps":   "false",
			"rules":  "false",
			"skills": "false",
		},
		"compat.codex": {
			"hooks":  "false",
			"skills": "false",
		},
		"compat.cursor": {
			"agents": "false",
			"hooks":  "false",
			"mcps":   "false",
			"rules":  "false",
			"skills": "false",
		},
		"features": {
			"campaigns":                  "false",
			"codebase_indexing":          "false",
			"managed_config":             "false",
			"mcp_auto_restart":           "false",
			"mcp_liveness_watchers":      "false",
			"mcp_recursive_config_watch": "false",
		},
		"paths": {
			"extra_rule_dirs":  "[]",
			"extra_skill_dirs": "[]",
		},
		"plugins": {
			"enabled": "[]",
			"paths":   "[]",
		},
	}
	gotSections := parseFlatTOMLSections(t, string(reqBytes))
	if !reflect.DeepEqual(gotSections, wantSections) {
		t.Fatalf("disposable requirements.toml lockdown sections mismatch:\ngot:  %#v\nwant: %#v", gotSections, wantSections)
	}
	if strings.Contains(string(reqBytes), fx.nativeHome.String()) || strings.Contains(string(reqBytes), "/Users/") {
		t.Fatalf("minimal disposable requirements.toml embedded native path: %s", reqBytes)
	}
	if _, err := os.Lstat(filepath.Join(wantGrokHome, "sandbox.toml")); !os.IsNotExist(err) {
		t.Fatalf("obsolete sandbox.toml was created: %v", err)
	}

	argv, err := profile.BuildArgv(inv)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(argv, "--trust") {
		t.Fatalf("Grok argv %q missing exact --trust flag", argv)
	}
	joined := strings.Join(argv, " ")
	for _, token := range []string{
		"--no-auto-update",
		"--no-leader",
		"--disable-web-search",
		"--no-subagents",
		"--no-plan",
		"--deny MCPTool",
		"--permission-mode bypassPermissions",
		"--trust",
		"--no-alt-screen",
		"--tools read_file,grep,list_dir,Write",
		"-m grok-4.7",
		"--reasoning-effort high",
		"--cwd " + fx.neutralCWD.String(),
	} {
		if !strings.Contains(joined, token) {
			t.Fatalf("Grok argv %q missing %q", joined, token)
		}
	}
	for _, arg := range argv {
		for _, forbidden := range []string{"agent", "stdio", "--sandbox", "--prompt", "-p"} {
			if arg == forbidden {
				t.Fatalf("Grok terminal argv %q retained forbidden flag %q", argv, forbidden)
			}
		}
	}
	for _, purpose := range []terminalInvocationPurpose{
		terminalPurposeReview,
		terminalPurposeExtraction,
		terminalPurposeQualification,
	} {
		purposeInv := inv
		purposeInv.Purpose = purpose
		purposeArgv, buildErr := profile.BuildArgv(purposeInv)
		if buildErr != nil {
			t.Fatalf("BuildArgv(purpose=%q): %v", purpose, buildErr)
		}
		if !slices.Contains(purposeArgv, "--trust") {
			t.Fatalf("Grok argv for purpose %q missing exact --trust flag: %q", purpose, purposeArgv)
		}
		if !slices.Contains(purposeArgv, "--cwd") || !slices.Contains(purposeArgv, fx.neutralCWD.String()) {
			t.Fatalf("Grok argv for purpose %q missing neutral --cwd binding: %q", purpose, purposeArgv)
		}
	}
	initialInput := profile.BuildInitialInput(inv)
	if !strings.Contains(initialInput, "line offsets until EOF") || !strings.Contains(initialInput, inv.PromptPath) || !strings.Contains(initialInput, inv.OutputPath) {
		t.Fatalf("Grok initial input missing pagination hint or paths: %q", initialInput)
	}
	extractInv := inv
	extractInv.Purpose = terminalPurposeExtraction
	extractInv.CompletionNonce = "nonce123"
	extractInput := profile.BuildInitialInput(extractInv)
	extractTrailer := string(profile.BuildPromptTrailer(extractInv))
	if !strings.Contains(extractInput, "brief plain-text refusal if refusing transcription") {
		t.Fatalf("Grok extraction initial input does not permit plain-text refusal: %q", extractInput)
	}
	if !strings.Contains(extractTrailer, "brief plain-text refusal if refusing transcription") ||
		!strings.Contains(extractTrailer, "After the end of your extraction output, add a newline") ||
		!strings.Contains(extractTrailer, terminalCompletionNoncePrefix+"nonce123\n") {
		t.Fatalf("Grok extraction trailer mismatch: %q", extractTrailer)
	}
}

func parseFlatTOMLSections(t *testing.T, body string) map[string]map[string]string {
	t.Helper()
	sections := map[string]map[string]string{"": {}}
	current := ""
	for lineNo, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			current = strings.TrimSpace(line[1 : len(line)-1])
			if current == "" {
				t.Fatalf("requirements.toml line %d: empty section header", lineNo+1)
			}
			if _, exists := sections[current]; !exists {
				sections[current] = map[string]string{}
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("requirements.toml line %d: malformed assignment %q", lineNo+1, line)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			t.Fatalf("requirements.toml line %d: empty key or value in %q", lineNo+1, line)
		}
		if _, dup := sections[current][key]; dup {
			t.Fatalf("requirements.toml line %d: duplicate key %q in section %q", lineNo+1, key, current)
		}
		sections[current][key] = value
	}
	return sections
}

func TestGrokRegistryLiveReviewExtractionAndLabelScopedDrain(t *testing.T) {
	for _, tc := range []struct {
		name      string
		scope     domain.LiveSourceScope
		purpose   ports.ProviderInvocationPurpose
		wantTools string
		wantBash  bool
		wantFile  string
	}{
		{
			name:      "workspace review shell-free",
			scope:     domain.LiveSourceWorkspace,
			purpose:   ports.ProviderInvocationInitial,
			wantTools: grokToolsWorkspaceReview,
			wantBash:  false,
			wantFile:  stagedOutputFilename,
		},
		{
			name:      "stage review B-1 Bash gate",
			scope:     domain.LiveSourceStage,
			purpose:   ports.ProviderInvocationInitial,
			wantTools: grokToolsGitReview,
			wantBash:  true,
			wantFile:  stagedOutputFilename,
		},
		{
			name:      "structured extraction shell-free",
			scope:     domain.LiveSourceStage,
			purpose:   ports.ProviderInvocationExtract,
			wantTools: grokToolsPromptBound,
			wantBash:  false,
			wantFile:  stagedExtractionOutputFilename,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			nativeHomeDir := filepath.Join(base, "native-home")
			projectDir := filepath.Join(base, "project")
			nsBaseDir := filepath.Join(base, "namespaces")
			for _, dir := range []string{filepath.Join(nativeHomeDir, ".grok"), projectDir, nsBaseDir} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(nativeHomeDir, ".grok", "auth.json"), []byte(`{"token":"test"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(projectDir, "main.go"), []byte("package main\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			git := func(args ...string) {
				cmd := exec.Command("/usr/bin/git", append([]string{"-C", projectDir}, args...)...)
				cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/var/empty", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"}
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("git %v: %v (%s)", args, err, out)
				}
			}
			git("init", "--quiet")
			git("add", "main.go")
			git("-c", "user.name=T", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "init")

			nativeHomeRoot, err := ports.NewAnchoredRoot(nativeHomeDir)
			if err != nil {
				t.Fatal(err)
			}
			reviewerHome, err := OpenReviewerHome(nativeHomeRoot, []byte("shared guide\n"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reviewerHome.Close() }()
			credRoot, err := ports.NewAnchoredRoot(filepath.Join(nativeHomeDir, ".grok"))
			if err != nil {
				t.Fatal(err)
			}
			cpRoots, cpLiterals, err := defaultControlPlanePathsForHome(nativeHomeRoot)
			if err != nil {
				t.Fatal(err)
			}
			sourceAdapter, err := gittargetadapter.NewLiveSourceAdapter(gittargetadapter.NewExecRunner(), []ports.AnchoredRoot{credRoot})
			if err != nil {
				t.Fatal(err)
			}
			projectRoot, err := ports.NewAnchoredRoot(projectDir)
			if err != nil {
				t.Fatal(err)
			}
			selector, err := ports.NewLiveSourceSelector(tc.scope, "")
			if err != nil {
				t.Fatal(err)
			}
			source, err := sourceAdapter.OpenLiveSource(ctx, projectRoot, selector)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = source.Close() }()
			baseExecution, err := ports.NewLiveReviewExecution(ctx, source, reviewerHome, []ports.AnchoredRoot{credRoot})
			if err != nil {
				t.Fatal(err)
			}
			execution, err := ports.NewLiveReviewExecutionWithControlPlane(baseExecution, cpRoots, cpLiterals)
			if err != nil {
				t.Fatal(err)
			}

			policy, err := RuntimeSafetyPolicyForFamily(CredentialSourceGrok)
			if err != nil {
				t.Fatal(err)
			}
			nsBase, err := NewNamespaceFactory(nsBaseDir)
			if err != nil {
				t.Fatal(err)
			}
			nsFactory, err := NewCredentialProjectingNamespaceFactoryWithPolicies(
				nsBase, nativeHomeDir,
				map[string]CredentialSourceFamily{"grok_live": CredentialSourceGrok},
				map[string]RuntimeSafetyPolicy{"grok_live": policy},
			)
			if err != nil {
				t.Fatal(err)
			}
			termRunner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
			defPort, err := (RuntimeBuilder{}).BuildProductionRuntime(ports.ProviderRuntimeSpec{
				Family:                      FamilyGrok,
				Instance:                    "grok_live",
				Executable:                  "/bin/echo",
				ExecutableSHA256:            "sha256:" + strings.Repeat("1", 64),
				Launcher:                    "/bin/echo",
				LauncherSHA256:              "sha256:" + strings.Repeat("1", 64),
				ProfileID:                   "grok_live",
				ProfileGeneration:           "live-test-gen",
				RuntimeSafetyPolicyIdentity: policy.Identity(),
				BaseArgv:                    []string{"/bin/echo"},
				TransportChannel:            ports.ProviderPacketChannelTerminal,
				TransportArgvIndex:          -1,
				WorkingDirectory:            reviewerHome.Root().String(),
				Timeout:                     2 * time.Minute,
			})
			if err != nil {
				t.Fatal(err)
			}
			def := defPort.(RuntimeDefinition)
			registry, err := NewProductionRegistryWithTerminalRunner(ctx, &countingRunner{}, termRunner, nsFactory, testSpawnVerifier{}, def)
			if err != nil {
				t.Fatal(err)
			}
			concreteLease := registry.namespaces["grok_live"].(*namespaceLease)

			var wantBody string
			if tc.purpose == ports.ProviderInvocationExtract {
				wantBody = `{"findings":[]}` + "\n"
			} else {
				wantBody = "# Grok Live Review\n\nClean.\n"
			}
			termRunner.runFunc = func(_ context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
				joined := strings.Join(req.Process().Argv(), " ")
				if !strings.Contains(joined, "--tools "+tc.wantTools) {
					t.Fatalf("argv %q missing --tools %s", joined, tc.wantTools)
				}
				boundary, guarded := req.Process().LiveReadOnlyBoundary()
				if !guarded || !boundary.PaneTTY() || boundary.OwnedPTY() || boundary.BashGate() != tc.wantBash {
					t.Fatalf("boundary guarded=%t paneTTY=%t ownedPTY=%t bash=%t, want true/true/false/%t", guarded, boundary.PaneTTY(), boundary.OwnedPTY(), boundary.BashGate(), tc.wantBash)
				}
				if len(boundary.ControlPlaneRoots()) == 0 {
					t.Fatal("ControlPlaneRoots missing from Grok live boundary")
				}
				if req.Labels()[terminalRegistryLabelKey] != registry.terminalGeneration {
					t.Fatalf("pane labels = %#v, want generation %q", req.Labels(), registry.terminalGeneration)
				}
				nonce := extractPromptNonce(t, req.PromptFilePath().String())
				outPath := findStagedOutputPath(t, concreteLease.root, tc.wantFile)
				if err := os.WriteFile(outPath, []byte(wantBody+terminalCompletionNoncePrefix+nonce+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return makeTerminalSessionObservation(t, termRunner, req, ports.TerminalExecutionObservationInput{
					ProgramStatus: ports.TerminalProgramStatusDone,
					TurnCount:     1,
				}, ports.ProcessTerminationExited, 0, true, nil, nil), nil
			}

			packetBytes := []byte("live review prompt")
			attempt, _ := domain.ParseAttemptID("a_019f596a-cf80-7c67-b265-f37053d51ccf")
			inv, err := ports.NewProviderInvocation(domain.RoleLogic, "grok_live", attempt, tc.purpose, packetBytes, "i_019f596a-cf80-7c67-b265-f37053d51ccd", "019f596a-cf80-7c67-b265-f37053d51cce", testStdinDigest(packetBytes))
			if err != nil {
				t.Fatal(err)
			}
			inv, err = ports.NewProviderInvocationInLiveSource(inv, execution)
			if err != nil {
				t.Fatal(err)
			}
			observed, err := registry.Observe(ctx, inv)
			if err != nil {
				t.Fatalf("Observe failed: %v", err)
			}
			if observed.Status() != ports.ProviderExecutionStatusSucceeded {
				t.Fatalf("status = %q diagnostic=%q cause=%q", observed.Status(), observed.DiagnosticCode(), observed.PrimaryCause())
			}
			if observed.OutputTransport() != ports.ProviderOutputTransportStdout {
				t.Fatalf("result_transport = %q, want stdout", observed.OutputTransport())
			}
			result, ok := observed.Result()
			if !ok || string(result.Stdout()) != wantBody {
				t.Fatalf("result = %q (ok=%t), want %q", result.Stdout(), ok, wantBody)
			}

			// Registry.Close must call ONLY label-scoped DrainLabeledPanes and NEVER Close().
			receipt, err := registry.Close(ctx)
			if err != nil || !receipt.Valid() {
				t.Fatalf("Registry.Close failed: %v", err)
			}
			if len(termRunner.drainCalls) != 1 || termRunner.drainCalls[0][0] != terminalRegistryLabelKey || termRunner.drainCalls[0][1] != registry.terminalGeneration {
				t.Fatalf("drain calls = %v, want 1 label-scoped call for %q", termRunner.drainCalls, registry.terminalGeneration)
			}
			if termRunner.closeCalls != 0 {
				t.Fatalf("Registry.Close illegally called terminalRunner.Close %d times", termRunner.closeCalls)
			}
		})
	}
}

func TestGrokQualificationVersionZeroHerdrAndProofBindsStagedAndRuntimeIdentity(t *testing.T) {
	ctx := context.Background()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	nativeHomeDir := filepath.Join(base, "native-home")
	nsBaseDir := filepath.Join(base, "namespaces")
	fixtureDir := filepath.Join(base, "fixture")
	for _, dir := range []string{filepath.Join(nativeHomeDir, ".grok"), nsBaseDir, fixtureDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(nativeHomeDir, ".grok", "auth.json"), []byte(`{"token":"test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := RuntimeSafetyPolicyForFamily(CredentialSourceGrok)
	if err != nil {
		t.Fatal(err)
	}
	nsBase, err := NewNamespaceFactory(nsBaseDir)
	if err != nil {
		t.Fatal(err)
	}
	nsFactory, err := NewCredentialProjectingNamespaceFactoryWithPolicies(
		nsBase, nativeHomeDir,
		map[string]CredentialSourceFamily{"grok_qual": CredentialSourceGrok},
		map[string]RuntimeSafetyPolicy{"grok_qual": policy},
	)
	if err != nil {
		t.Fatal(err)
	}
	termRunner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
	executable, err := filepath.EvalSymlinks("/bin/echo")
	if err != nil {
		t.Fatal(err)
	}
	defPort, err := (RuntimeBuilder{}).BuildProductionRuntime(ports.ProviderRuntimeSpec{
		Family:                      FamilyGrok,
		Instance:                    "grok_qual",
		Executable:                  executable,
		ExecutableSHA256:            "sha256:" + strings.Repeat("1", 64),
		Launcher:                    executable,
		LauncherSHA256:              "sha256:" + strings.Repeat("1", 64),
		ProfileID:                   "grok_qual",
		ProfileGeneration:           "qual-gen",
		RuntimeSafetyPolicyIdentity: policy.Identity(),
		BaseArgv:                    []string{executable},
		TransportChannel:            ports.ProviderPacketChannelTerminal,
		TransportArgvIndex:          -1,
		WorkingDirectory:            "/private/var/empty",
		Timeout:                     2 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	def := defPort.(RuntimeDefinition)

	versionRunner := &neutralVersionProbeRunner{
		observations: []ports.ProcessObservation{
			testProcessObservation(t, []byte("grok 1.0.89 (abcdef123456)\n"), nil, ports.ProcessTerminationExited, 0),
		},
	}
	registry, err := NewProductionRegistryWithTerminalRunner(ctx, versionRunner, termRunner, nsFactory, testSpawnVerifier{}, def)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = registry.Close(ctx) }()
	qualNS, ok := registry.QualificationNamespace("grok_qual")
	if !ok {
		t.Fatal("missing qualification namespace")
	}
	concreteLease := registry.namespaces["grok_qual"].(*namespaceLease)

	snapshotID, err := ports.NewWorkspaceSnapshotIdentity(
		fixtureDir, "snapshot-0123456789abcdef0123456789abcdef",
		"sha256:"+strings.Repeat("a", 64), "fixture-policy", 1, 1, 10, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	validatedFixtureRoot, err := ports.NewValidatedWorkspaceRoot(fixtureDir, snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &currentProbeFixture{root: validatedFixtureRoot, identity: snapshotID, role: domain.RoleLogic}
	stagedJSON := []byte(`{"root":"nonce","link":"linked","role":"logic"}`)
	screenNoise := []byte("noisy TUI frame content that must never enter OutputSHA256")
	var capturedVersionCWD string
	sawTermCallsAtVersion := -1
	versionRunner.onRun = func() {
		sawTermCallsAtVersion = len(termRunner.requests)
	}
	termRunner.runFunc = func(_ context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
		if len(versionRunner.requests) != 1 {
			t.Fatalf("expected --version to run before capability; got %d plain calls", len(versionRunner.requests))
		}
		capturedVersionCWD = versionRunner.requests[0].WorkingDirectory()
		if req.Process().WorkingDirectory() != filepath.Join(nativeHomeDir, ".mulgae", "home") {
			t.Fatalf("Grok capability cwd = %q, want neutral ~/.mulgae/home", req.Process().WorkingDirectory())
		}
		// Defect #6: qualification pane must carry Registry.terminalGeneration,
		// not the per-instance namespace generation.
		if got := req.Labels()[terminalRegistryLabelKey]; got != registry.terminalGeneration {
			t.Fatalf("Grok qualification pane label %s = %q, want registry terminalGeneration %q (namespace gen %q)",
				terminalRegistryLabelKey, got, registry.terminalGeneration, qualNS.Generation())
		}
		outPath := findStagedOutputPath(t, concreteLease.root, stagedProbeOutputFilename)
		if err := os.WriteFile(outPath, stagedJSON, 0o600); err != nil {
			t.Fatal(err)
		}
		return makeTerminalSessionObservation(t, termRunner, req, ports.TerminalExecutionObservationInput{
			ProgramStatus: ports.TerminalProgramStatusDone,
			TurnCount:     1,
			ScreenCapture: screenNoise,
		}, ports.ProcessTerminationExited, 0, true, screenNoise, screenNoise), nil
	}

	probe, err := NewCurrentProbeWithTerminalRunner(versionRunner, &currentProbeVerifier{}, termRunner)
	if err != nil {
		t.Fatal(err)
	}
	res, err := probe.QualifyCurrent(ctx, CurrentProbeRequest{
		Definition: def, Namespace: qualNS, Fixture: fixture, Invocation: NativeProbeInvocation{},
		Now: time.Unix(2000, 0).UTC(), TTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("QualifyCurrent(Grok) failed: %v (unwrap=%v; versionCalls=%d termCalls=%d)", err, errors.Unwrap(err), len(versionRunner.requests), len(termRunner.requests))
	}
	if sawTermCallsAtVersion != 0 || len(versionRunner.requests) != 1 || len(termRunner.requests) != 1 {
		t.Fatalf("sawTermCallsAtVersion=%d plain calls=%d terminal calls=%d, want 0 / 1 / 1", sawTermCallsAtVersion, len(versionRunner.requests), len(termRunner.requests))
	}
	// Closing registry after qualification (without any Observe call) must drain
	// panes tagged with registry.terminalGeneration and never close the shared
	// terminalRunner.
	if _, closeErr := registry.Close(ctx); closeErr != nil {
		t.Fatalf("registry.Close after qualification failed: %v", closeErr)
	}
	if len(termRunner.drainCalls) != 1 || termRunner.drainCalls[0] != [2]string{terminalRegistryLabelKey, registry.terminalGeneration} {
		t.Fatalf("registry.Close drainCalls after Grok qualification = %v, want [[%s %s]]",
			termRunner.drainCalls, terminalRegistryLabelKey, registry.terminalGeneration)
	}
	if termRunner.closeCalls != 0 {
		t.Fatalf("registry.Close must never close shared terminalRunner; got %d close calls", termRunner.closeCalls)
	}
	wantNeutral := filepath.Join(nativeHomeDir, ".mulgae", "home")
	if capturedVersionCWD != wantNeutral {
		t.Fatalf("Grok --version cwd = %q, want neutral %q", capturedVersionCWD, wantNeutral)
	}
	if res.Version != "1.0.89" {
		t.Fatalf("version = %q, want 1.0.89", res.Version)
	}
	wantOutSum := sha256.Sum256(stagedJSON)
	wantOutSHA := "sha256:" + hex.EncodeToString(wantOutSum[:])
	rtDefID, err := currentProbeRuntimeDefinitionIdentity(def)
	if err != nil {
		t.Fatal(err)
	}
	wantCapID, err := currentProbeEvidenceID("capability", rtDefID, []string{wantOutSHA})
	if err != nil {
		t.Fatal(err)
	}
	receiptByKind := make(map[string]CurrentProbeReceipt, len(res.Receipts))
	for _, receipt := range res.Receipts {
		receiptByKind[receipt.Kind] = receipt
	}
	if receiptByKind["capability"].EvidenceID != wantCapID {
		t.Fatalf("capability receipt = %q, want staged JSON hash receipt %q (must not hash screen capture)", receiptByKind["capability"].EvidenceID, wantCapID)
	}
	authReceipt, ok := receiptByKind["direct-execution-authority"]
	if !ok || authReceipt.EvidenceID == "" {
		t.Fatalf("direct-execution-authority receipt missing: %#v", receiptByKind)
	}
	// Verify herdr-core identity change changes the direct-execution-authority ID.
	altID, err := ports.NewTerminalRuntimeIdentity("/opt/homebrew/bin/herdr-core", "sha256:"+strings.Repeat("b", 64), "0.1.0", 1)
	if err != nil {
		t.Fatal(err)
	}
	termRunner.identity = altID
	versionRunner.observations = []ports.ProcessObservation{
		testProcessObservation(t, []byte("grok 1.0.89 (abcdef123456)\n"), nil, ports.ProcessTerminationExited, 0),
	}
	versionRunner.requests = nil
	// Use a fresh namespace so the second run binds the alternate herdr-core identity.
	registry2, err := NewProductionRegistryWithTerminalRunner(ctx, versionRunner, termRunner, nsFactory, testSpawnVerifier{}, def)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = registry2.Close(ctx) }()
	qualNS2, _ := registry2.QualificationNamespace("grok_qual")
	concreteLease = registry2.namespaces["grok_qual"].(*namespaceLease)
	termRunner.runFunc = func(_ context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
		if got := req.Labels()[terminalRegistryLabelKey]; got != registry2.terminalGeneration {
			t.Fatalf("second Grok qualification pane label = %q, want %q", got, registry2.terminalGeneration)
		}
		outPath := findStagedOutputPath(t, concreteLease.root, stagedProbeOutputFilename)
		if err := os.WriteFile(outPath, stagedJSON, 0o600); err != nil {
			t.Fatal(err)
		}
		return makeTerminalSessionObservation(t, termRunner, req, ports.TerminalExecutionObservationInput{
			ProgramStatus: ports.TerminalProgramStatusDone,
			TurnCount:     1,
			ScreenCapture: screenNoise,
		}, ports.ProcessTerminationExited, 0, true, screenNoise, screenNoise), nil
	}
	res2, err := probe.QualifyCurrent(ctx, CurrentProbeRequest{
		Definition: def, Namespace: qualNS2, Fixture: fixture, Invocation: NativeProbeInvocation{},
		Now: time.Unix(2000, 0).UTC(), TTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("second QualifyCurrent(Grok) failed: %v", err)
	}
	var authID2 string
	for _, receipt := range res2.Receipts {
		if receipt.Kind == "direct-execution-authority" {
			authID2 = receipt.EvidenceID
		}
	}
	if authID2 == "" || authID2 == authReceipt.EvidenceID {
		t.Fatalf("changing herdr-core SHA-256 did not change direct-execution-authority ID (%q == %q)", authID2, authReceipt.EvidenceID)
	}
	// Also verify same-namespace herdr-core identity drift fails closed!
	if err := concreteLease.bindGrokTerminalRuntimeIdentity(defaultFakeTerminalIdentity(t)); err == nil {
		t.Fatal("same-namespace herdr-core identity drift was not rejected")
	}
}

type neutralVersionProbeRunner struct {
	observations []ports.ProcessObservation
	requests     []ports.ProcessRequest
	onRun        func()
}

func (r *neutralVersionProbeRunner) Run(_ context.Context, req ports.ProcessRequest) (ports.ProcessObservation, error) {
	if r.onRun != nil {
		r.onRun()
	}
	r.requests = append(r.requests, req)
	dir, _, ok := req.LaunchDirectory()
	if !ok || dir == nil {
		return ports.ProcessObservation{}, errors.New("missing neutral launch directory")
	}
	_ = dir.Close()
	if len(r.observations) == 0 {
		return ports.ProcessObservation{}, errors.New("no version observation queued")
	}
	obs := r.observations[0]
	r.observations = r.observations[1:]
	return obs, nil
}

type tripwireTerminalRunner struct{ t *testing.T }

func (r tripwireTerminalRunner) RunTerminal(context.Context, ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
	r.t.Fatal("unexpected herdr-core RunTerminal for non-Grok provider")
	return ports.TerminalExecutionObservation{}, errors.New("forbidden")
}
func (r tripwireTerminalRunner) DrainLabeledPanes(context.Context, string, string) error {
	r.t.Fatal("unexpected herdr-core DrainLabeledPanes for non-Grok provider")
	return errors.New("forbidden")
}
func (r tripwireTerminalRunner) RuntimeIdentity(context.Context) (ports.TerminalRuntimeIdentity, error) {
	r.t.Fatal("unexpected herdr-core RuntimeIdentity for non-Grok provider")
	return ports.TerminalRuntimeIdentity{}, errors.New("forbidden")
}
func (r tripwireTerminalRunner) Close(context.Context) error {
	r.t.Fatal("unexpected herdr-core Close from Registry")
	return errors.New("forbidden")
}

func TestNonGrokFamiliesNeverTouchHerdrCoreAndReceiveSharedControlPlaneRoots(t *testing.T) {
	ctx := context.Background()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	nativeHomeDir := filepath.Join(base, "native-home")
	projectDir := filepath.Join(base, "project")
	for _, dir := range []string{
		filepath.Join(nativeHomeDir, ".zcode", "v2"),
		filepath.Join(nativeHomeDir, ".codex"),
		filepath.Join(nativeHomeDir, ".cursor"),
		filepath.Join(nativeHomeDir, ".gemini"),
		projectDir,
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(projectDir, "a.txt"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	nativeHomeRoot, _ := ports.NewAnchoredRoot(nativeHomeDir)
	reviewerHome, err := OpenReviewerHome(nativeHomeRoot, []byte("guide\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reviewerHome.Close() }()
	cpRoots, cpLiterals, err := defaultControlPlanePathsForHome(nativeHomeRoot)
	if err != nil {
		t.Fatal(err)
	}
	credRoot, _ := ports.NewAnchoredRoot(filepath.Join(nativeHomeDir, ".codex"))
	sourceAdapter, err := gittargetadapter.NewLiveSourceAdapter(gittargetadapter.NewExecRunner(), []ports.AnchoredRoot{credRoot})
	if err != nil {
		t.Fatal(err)
	}
	projectRoot, _ := ports.NewAnchoredRoot(projectDir)
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	source, err := sourceAdapter.OpenLiveSource(ctx, projectRoot, selector)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Close() }()
	baseExecution, err := ports.NewLiveReviewExecution(ctx, source, reviewerHome, []ports.AnchoredRoot{credRoot})
	if err != nil {
		t.Fatal(err)
	}
	execution, err := ports.NewLiveReviewExecutionWithControlPlane(baseExecution, cpRoots, cpLiterals)
	if err != nil {
		t.Fatal(err)
	}

	for _, family := range []string{FamilyZcode, FamilyCodex, FamilyAgy} {
		t.Run(family, func(t *testing.T) {
			nsRoot := filepath.Join(base, "ns-"+family)
			nsBase, err := NewNamespaceFactory(nsRoot)
			if err != nil {
				t.Fatal(err)
			}
			instance := family + "_ctrlplane"
			var nsFactory ports.ProviderNamespaceFactory = nsBase
			if family == FamilyAgy {
				agyPolicy, policyErr := RuntimeSafetyPolicyForFamily(CredentialSourceAgy)
				if policyErr != nil {
					t.Fatal(policyErr)
				}
				agyAuthDir := filepath.Join(nativeHomeDir, ".gemini", "antigravity-cli")
				if mkErr := os.MkdirAll(agyAuthDir, 0o700); mkErr != nil {
					t.Fatal(mkErr)
				}
				if wErr := os.WriteFile(filepath.Join(agyAuthDir, "antigravity-oauth-token"), []byte("test-token"), 0o600); wErr != nil {
					t.Fatal(wErr)
				}
				nsFactory, err = NewCredentialProjectingNamespaceFactoryWithPolicies(
					nsBase, nativeHomeDir,
					map[string]CredentialSourceFamily{instance: CredentialSourceAgy},
					map[string]RuntimeSafetyPolicy{instance: agyPolicy},
				)
				if err != nil {
					t.Fatal(err)
				}
			}
			var capturedReq ports.ProcessRequest
			runner := &liveCaptureRunner{
				onConverse: func(req ports.ProcessRequest) (ports.ProcessObservation, error) {
					capturedReq = req
					if dir, _, ok := req.LaunchDirectory(); ok && dir != nil {
						_ = dir.Close()
					}
					return protocolTeardownObservation(t, nil), errors.New("stop-after-capture")
				},
			}
			def := testProfile(t, family, instance, "", "")
			if family == FamilyZcode {
				def.zcodeProviderConfig = "/Applications/ZCode.app/Contents/Resources/config/provider/zcode-builtin.json"
			}
			registry, err := NewRegistryWithNamespaceFactory(runner, nsFactory, def)
			if err != nil {
				t.Fatal(err)
			}
			if family == FamilyAgy {
				if err := (retainedQualificationNamespace{lease: registry.namespaces[instance]}).recordAgyQualification(def, "1.2.9"); err != nil {
					t.Fatal(err)
				}
			}
			registry.terminalRunner = tripwireTerminalRunner{t: t}
			inv := testInvocation(t, instance)
			inv, err = ports.NewProviderInvocationInLiveSource(inv, execution)
			if err != nil {
				t.Fatal(err)
			}
			obs, obsErr := registry.Observe(ctx, inv)
			if _, err := registry.Close(ctx); err != nil {
				t.Fatalf("Registry.Close(%s): %v", family, err)
			}
			if capturedReq.Executable() == "" {
				t.Fatalf("%s did not reach runner.Converse: status=%q diag=%q cause=%q err=%v", family, obs.Status(), obs.DiagnosticCode(), obs.PrimaryCause(), obsErr)
			}
			if family == FamilyCodex {
				joined := strings.Join(capturedReq.Argv(), " ")
				for _, root := range cpRoots {
					if !strings.Contains(joined, root.String()) {
						t.Fatalf("Codex permissions.mulgae argv missing control-plane root %q: %s", root.String(), joined)
					}
				}
				return
			}
			boundary, guarded := capturedReq.LiveReadOnlyBoundary()
			if !guarded {
				t.Fatalf("%s live launch missing LiveReadOnlyBoundary", family)
			}
			for _, root := range cpRoots {
				if !anchoredContains(boundary.ControlPlaneRoots(), root.String()) {
					t.Fatalf("%s boundary missing control-plane root %q", family, root.String())
				}
			}
			if family == FamilyAgy && !boundary.OwnedPTY() {
				t.Fatal("AGY lost OwnedPTY boundary clause")
			}
			if family != FamilyAgy && boundary.OwnedPTY() {
				t.Fatalf("%s unexpectedly acquired OwnedPTY clause", family)
			}
		})
	}
}

type liveCaptureRunner struct {
	onConverse func(ports.ProcessRequest) (ports.ProcessObservation, error)
}

func (r *liveCaptureRunner) Run(_ context.Context, req ports.ProcessRequest) (ports.ProcessObservation, error) {
	return r.onConverse(req)
}
func (r *liveCaptureRunner) Converse(_ context.Context, req ports.ProcessRequest, _ ports.ProviderSessionDriver) (ports.ProcessObservation, error) {
	return r.onConverse(req)
}

// TestGrokInstalledBinaryInsideProtectedGrokHomeExecutesUnderSeatbelt verifies
// empirical Pre-check 0 offline on Darwin: a real Mach-O binary installed inside
// ~/.grok/downloads/grok-test executes cleanly while ~/.grok/auth.json remains
// protected against file-read* (EPERM) without widening ~/.grok denies.
func TestGrokInstalledBinaryInsideProtectedGrokHomeExecutesUnderSeatbelt(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fakeHome := filepath.Join(base, "home")
	grokDir := filepath.Join(fakeHome, ".grok")
	downloadsDir := filepath.Join(grokDir, "downloads")
	writableDir := filepath.Join(base, "writable")
	neutralDir := filepath.Join(fakeHome, ".mulgae", "home")
	for _, dir := range []string{downloadsDir, writableDir, neutralDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Copy this ad-hoc signed Darwin arm64 test Mach-O binary into
	// ~/.grok/downloads/ so AMFI permits execution without external codesign.
	selfExec, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	selfBytes, err := os.ReadFile(selfExec)
	if err != nil {
		t.Fatal(err)
	}
	installedGrok := filepath.Join(downloadsDir, "grok-1.0.89-test")
	if err := os.WriteFile(installedGrok, selfBytes, 0o700); err != nil {
		t.Fatal(err)
	}
	authPath := filepath.Join(grokDir, "auth.json")
	if err := os.WriteFile(authPath, []byte(`{"secret":"DO_NOT_READ"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	controlDir := filepath.Join(base, "control")
	if err := os.MkdirAll(controlDir, 0o700); err != nil {
		t.Fatal(err)
	}
	homeRoot, _ := ports.NewAnchoredRoot(fakeHome)
	grokRoot, _ := ports.NewAnchoredRoot(grokDir)
	writableRoot, _ := ports.NewAnchoredRoot(writableDir)
	neutralRoot, _ := ports.NewAnchoredRoot(neutralDir)
	controlRoot, _ := ports.NewAnchoredRoot(controlDir)
	boundary, err := ports.NewLiveReadOnlyBoundary([]ports.AnchoredRoot{neutralRoot}, []ports.AnchoredRoot{grokRoot}, writableRoot)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err = ports.NewLiveReadOnlyBoundaryWithControlPlane(boundary, []ports.AnchoredRoot{controlRoot}, nil)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err = ports.NewLiveReadOnlyBoundaryWithPaneTTY(boundary, homeRoot)
	if err != nil {
		t.Fatal(err)
	}

	builder := processadapter.NewPaneLaunchBuilder()
	packet, _ := ports.NewProviderPacketFromBytes([]byte("test"))
	binding, _ := ports.NewTerminalProviderPacketBinding(packet)

	// 1. Executing the Mach-O binary inside ~/.grok/downloads/ under the
	// generated Seatbelt profile must succeed.
	execReq, err := ports.NewProviderProcessRequest(installedGrok, []string{installedGrok, "GROK_EXEC_OK"}, nil, neutralRoot.String(), binding, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	execReq, err = ports.NewLiveReadOnlyProcessRequest(execReq, boundary)
	if err != nil {
		t.Fatal(err)
	}
	launchDir1, err := os.Open(neutralRoot.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = launchDir1.Close() }()
	execReq, err = ports.NewNeutralBoundProcessRequest(execReq, neutralRoot, launchDir1)
	if err != nil {
		t.Fatal(err)
	}
	paneReq1, err := ports.NewPaneLaunchRequest(execReq, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	spec1, err := builder.BuildPaneLaunch(context.Background(), paneReq1)
	if err != nil {
		t.Fatalf("BuildPaneLaunch(installedGrok): %v", err)
	}
	cmd1 := exec.Command("/usr/bin/sandbox-exec", "-D", "PANE_TTY=/dev/ttys999", "-f", spec1.ProfileFilePath(), "--", installedGrok, "-test.run=^TestGrokExecSentinelHelper$")
	cmd1.Dir = neutralRoot.String()
	cmd1.Env = []string{"PATH=/usr/bin:/bin", "MULGAE_GROK_EXEC_HELPER=1"}
	out1, err := cmd1.CombinedOutput()
	if err != nil || !bytes.Contains(out1, []byte("GROK_EXEC_OK")) {
		t.Fatalf("executing Mach-O inside ~/.grok/downloads/ failed: err=%v out=%q", err, out1)
	}

	// 2. Reading ~/.grok/auth.json under the EXACT same Seatbelt profile must
	// fail with EPERM (no widening of ~/.grok denies).
	cmd2 := exec.Command("/usr/bin/sandbox-exec", "-D", "PANE_TTY=/dev/ttys999", "-f", spec1.ProfileFilePath(), "--", "/bin/cat", authPath)
	cmd2.Dir = neutralRoot.String()
	out2, err := cmd2.CombinedOutput()
	if err == nil || bytes.Contains(out2, []byte("DO_NOT_READ")) {
		t.Fatalf("~/.grok/auth.json read succeeded under Seatbelt: err=%v out=%q", err, out2)
	}
	if !strings.Contains(string(out2), "Operation not permitted") {
		t.Fatalf("expected Operation not permitted reading ~/.grok/auth.json, got %q", out2)
	}
}

func TestGrokExecSentinelHelper(t *testing.T) {
	if os.Getenv("MULGAE_GROK_EXEC_HELPER") != "1" {
		return
	}
	_, _ = os.Stdout.WriteString("GROK_EXEC_OK\n")
}

// Keep json import used for verifying valid probe JSON structure.
var _ = json.Valid

func TestGrokQualificationVersionBelowMinimumNeverStartsTerminalRunner(t *testing.T) {
	ctx := context.Background()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	nativeHomeDir := filepath.Join(base, "native-home")
	nsBaseDir := filepath.Join(base, "namespaces")
	fixtureDir := filepath.Join(base, "fixture")
	for _, dir := range []string{filepath.Join(nativeHomeDir, ".grok"), nsBaseDir, fixtureDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(nativeHomeDir, ".grok", "auth.json"), []byte(`{"token":"test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := RuntimeSafetyPolicyForFamily(CredentialSourceGrok)
	if err != nil {
		t.Fatal(err)
	}
	nsBase, err := NewNamespaceFactory(nsBaseDir)
	if err != nil {
		t.Fatal(err)
	}
	nsFactory, err := NewCredentialProjectingNamespaceFactoryWithPolicies(
		nsBase, nativeHomeDir,
		map[string]CredentialSourceFamily{"grok_old": CredentialSourceGrok},
		map[string]RuntimeSafetyPolicy{"grok_old": policy},
	)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := filepath.EvalSymlinks("/bin/echo")
	if err != nil {
		t.Fatal(err)
	}
	defPort, err := (RuntimeBuilder{}).BuildProductionRuntime(ports.ProviderRuntimeSpec{
		Family: FamilyGrok, Instance: "grok_old", Executable: executable,
		ExecutableSHA256: "sha256:" + strings.Repeat("1", 64),
		Launcher:         executable, LauncherSHA256: "sha256:" + strings.Repeat("1", 64),
		ProfileID: "grok_old", ProfileGeneration: "old-gen",
		RuntimeSafetyPolicyIdentity: policy.Identity(),
		BaseArgv:                    []string{executable},
		TransportChannel:            ports.ProviderPacketChannelTerminal,
		TransportArgvIndex:          -1,
		WorkingDirectory:            "/private/var/empty",
		Timeout:                     2 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	def := defPort.(RuntimeDefinition)
	versionRunner := &neutralVersionProbeRunner{
		observations: []ports.ProcessObservation{
			testProcessObservation(t, []byte("grok 1.0.40 (eb1a2256660d) [stable]\n"), nil, ports.ProcessTerminationExited, 0),
		},
	}
	termRunner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
	registry, err := NewProductionRegistryWithTerminalRunner(ctx, versionRunner, termRunner, nsFactory, testSpawnVerifier{}, def)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = registry.Close(ctx) }()
	qualNS, _ := registry.QualificationNamespace("grok_old")
	snapshotID, err := ports.NewWorkspaceSnapshotIdentity(
		fixtureDir, "snapshot-0123456789abcdef0123456789abcdef",
		"sha256:"+strings.Repeat("a", 64), "fixture-policy", 1, 1, 10, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	validatedFixtureRoot, err := ports.NewValidatedWorkspaceRoot(fixtureDir, snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &currentProbeFixture{root: validatedFixtureRoot, identity: snapshotID, role: domain.RoleLogic}
	probe, err := NewCurrentProbeWithTerminalRunner(versionRunner, &currentProbeVerifier{}, termRunner)
	if err != nil {
		t.Fatal(err)
	}
	_, qualErr := probe.QualifyCurrent(ctx, CurrentProbeRequest{
		Definition: def, Namespace: qualNS, Fixture: fixture, Invocation: NativeProbeInvocation{},
		Now: time.Unix(2000, 0).UTC(), TTL: time.Minute,
	})
	if qualErr == nil {
		t.Fatal("QualifyCurrent accepted Grok 1.0.40 below minimum 1.0.89")
	}
	if len(termRunner.requests) != 0 || termRunner.runtimeIDCalls != 0 {
		t.Fatalf("failed --version still invoked terminalRunner: requests=%d runtimeIDCalls=%d",
			len(termRunner.requests), termRunner.runtimeIDCalls)
	}
}

func TestClassifyProbeFailurePreservesTerminalDriverStatusPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    ports.ProviderExecutionStatus
		diag      string
		cause     domain.RuntimeDiagnosticCause
		cleanup   domain.RuntimeDiagnosticCause
		wantClass domain.FailureClass
	}{
		{
			name:      "StartSecurity maps to FailureSecurityPolicy",
			status:    ports.ProviderExecutionStatusSecurityViolation,
			diag:      "process_security",
			cause:     domain.DiagnosticCauseProviderSpawnFailed,
			wantClass: domain.FailureSecurityPolicy,
		},
		{
			name:      "MutationViolation maps to FailureSecurityPolicy",
			status:    ports.ProviderExecutionStatusMutationViolation,
			diag:      "process_mutation",
			cause:     domain.DiagnosticCauseProviderSpawnFailed,
			wantClass: domain.FailureSecurityPolicy,
		},
		{
			name:      "StartConfiguration maps to FailureConfiguration",
			status:    ports.ProviderExecutionStatusConfigurationViolation,
			diag:      "process_configuration",
			cause:     domain.DiagnosticCauseProviderSpawnFailed,
			wantClass: domain.FailureConfiguration,
		},
		{
			name:      "StartFailed maps to FailureInternal",
			status:    ports.ProviderExecutionStatusInternalFailure,
			diag:      "process_internal",
			cause:     domain.DiagnosticCauseProviderSpawnFailed,
			wantClass: domain.FailureInternal,
		},
		{
			name:      "Cleanup failure on terminalDriverFailure maps to FailureSecurityPolicy",
			status:    ports.ProviderExecutionStatusUnavailable,
			diag:      "provider_execution_failed",
			cause:     domain.DiagnosticCauseProviderExecutionFailed,
			cleanup:   domain.DiagnosticCauseProcessGroupCleanupFailed,
			wantClass: domain.FailureSecurityPolicy,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tf := newTerminalDriverFailure(tc.status, tc.diag, tc.cause, tc.cleanup, errors.New("start failed"))
			classified := classifyProbeFailure(context.Background(), FamilyGrok, tf, nil, nil)
			var failure *domain.Failure
			if !errors.As(classified, &failure) || failure.Class() != tc.wantClass {
				t.Fatalf("classifyProbeFailure(%s) = %#v, want class %q", tc.name, failure, tc.wantClass)
			}
		})
	}
}

func TestUnsafeHerdrCoreBinaryFailsClosedSecurityInQualificationAndLiveExecution(t *testing.T) {
	ctx := context.Background()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	nativeHomeDir := filepath.Join(base, "native-home")
	nsBaseDir := filepath.Join(base, "namespaces")
	fixtureDir := filepath.Join(base, "fixture")
	projectDir := filepath.Join(base, "project")
	for _, dir := range []string{filepath.Join(nativeHomeDir, ".grok"), nsBaseDir, fixtureDir, projectDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(nativeHomeDir, ".grok", "auth.json"), []byte(`{"token":"test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Create a tampered world-writable herdr-core binary and point
	// MULGAE_HERDR_CORE_BIN at it so herdr.Session.ensureStarted fails with
	// herdr.ErrUnsafeExecutable.
	unsafeBin := filepath.Join(base, "unsafe-herdr-core")
	if err := os.WriteFile(unsafeBin, []byte("#!/bin/sh\nexit 0\n"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeBin, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Setenv(herdradapter.EnvHerdrCoreBin, unsafeBin)

	nativeHomeRoot, err := ports.NewAnchoredRoot(nativeHomeDir)
	if err != nil {
		t.Fatal(err)
	}
	session, err := herdradapter.NewSession(herdradapter.SessionOptions{
		Clock:         runtimeadapter.SystemClock{},
		LaunchBuilder: processadapter.NewPaneLaunchBuilder(),
		NativeHome:    nativeHomeRoot,
		BaseDir:       filepath.Join(base, "mgh-unsafe"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close(ctx) }()

	policy, err := RuntimeSafetyPolicyForFamily(CredentialSourceGrok)
	if err != nil {
		t.Fatal(err)
	}
	nsBase, err := NewNamespaceFactory(nsBaseDir)
	if err != nil {
		t.Fatal(err)
	}
	nsFactory, err := NewCredentialProjectingNamespaceFactoryWithPolicies(
		nsBase, nativeHomeDir,
		map[string]CredentialSourceFamily{"grok_unsafe": CredentialSourceGrok},
		map[string]RuntimeSafetyPolicy{"grok_unsafe": policy},
	)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := filepath.EvalSymlinks("/bin/echo")
	if err != nil {
		t.Fatal(err)
	}
	defPort, err := (RuntimeBuilder{}).BuildProductionRuntime(ports.ProviderRuntimeSpec{
		Family: FamilyGrok, Instance: "grok_unsafe", Executable: executable,
		ExecutableSHA256: "sha256:" + strings.Repeat("1", 64),
		Launcher:         executable, LauncherSHA256: "sha256:" + strings.Repeat("1", 64),
		ProfileID: "grok_unsafe", ProfileGeneration: "unsafe-gen",
		RuntimeSafetyPolicyIdentity: policy.Identity(),
		BaseArgv:                    []string{executable},
		TransportChannel:            ports.ProviderPacketChannelTerminal,
		TransportArgvIndex:          -1,
		WorkingDirectory:            "/private/var/empty",
		Timeout:                     2 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	def := defPort.(RuntimeDefinition)

	versionRunner := &neutralVersionProbeRunner{
		observations: []ports.ProcessObservation{
			testProcessObservation(t, []byte("grok 1.0.89 (abcdef123456)\n"), nil, ports.ProcessTerminationExited, 0),
		},
	}
	registry, err := NewProductionRegistryWithTerminalRunner(ctx, versionRunner, session, nsFactory, testSpawnVerifier{}, def)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = registry.Close(ctx) }()

	// 1. Qualification path must fail closed with FailureSecurityPolicy.
	qualNS, _ := registry.QualificationNamespace("grok_unsafe")
	snapshotID, err := ports.NewWorkspaceSnapshotIdentity(
		fixtureDir, "snapshot-0123456789abcdef0123456789abcdef",
		"sha256:"+strings.Repeat("a", 64), "fixture-policy", 1, 1, 10, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	validatedFixtureRoot, err := ports.NewValidatedWorkspaceRoot(fixtureDir, snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &currentProbeFixture{root: validatedFixtureRoot, identity: snapshotID, role: domain.RoleLogic}
	probe, err := NewCurrentProbeWithTerminalRunner(versionRunner, &currentProbeVerifier{}, session)
	if err != nil {
		t.Fatal(err)
	}
	_, qualErr := probe.QualifyCurrent(ctx, CurrentProbeRequest{
		Definition: def, Namespace: qualNS, Fixture: fixture, Invocation: NativeProbeInvocation{},
		Now: time.Unix(2000, 0).UTC(), TTL: time.Minute,
	})
	var failure *domain.Failure
	if !errors.As(qualErr, &failure) || failure.Class() != domain.FailureSecurityPolicy {
		t.Fatalf("qualification with unsafe herdr-core = %#v (err=%v), want FailureSecurityPolicy", failure, qualErr)
	}

	// 2. Live execution path must fail closed with ProviderExecutionStatusSecurityViolation.
	reviewerHome, err := OpenReviewerHome(nativeHomeRoot, []byte("guide\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reviewerHome.Close() }()
	grokCredRoot, _ := ports.NewAnchoredRoot(filepath.Join(nativeHomeDir, ".grok"))
	sourceAdapter, err := gittargetadapter.NewLiveSourceAdapter(gittargetadapter.NewExecRunner(), []ports.AnchoredRoot{grokCredRoot})
	if err != nil {
		t.Fatal(err)
	}
	projectRoot, _ := ports.NewAnchoredRoot(projectDir)
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	source, err := sourceAdapter.OpenLiveSource(ctx, projectRoot, selector)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Close() }()
	execution, err := ports.NewLiveReviewExecution(ctx, source, reviewerHome, []ports.AnchoredRoot{grokCredRoot})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := ports.NewProviderInvocationInLiveSource(testInvocation(t, "grok_unsafe"), execution)
	if err != nil {
		t.Fatal(err)
	}
	obs, obsErr := registry.Observe(ctx, inv)
	if obsErr != nil {
		t.Fatalf("Observe(unsafe herdr-core) returned raw error %v, want partial SecurityViolation observation", obsErr)
	}
	if obs.Status() != ports.ProviderExecutionStatusSecurityViolation || obs.PrimaryCause() != domain.DiagnosticCauseTransportVerificationFailed {
		t.Fatalf("Observe(unsafe herdr-core) = status:%q cause:%q, want security_violation / transport_verification_failed",
			obs.Status(), obs.PrimaryCause())
	}
}

func TestControlPlanePathsFailClosedAndExpandMissingLeafSymlinks(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	homeRoot, err := ports.NewAnchoredRoot(filepath.Join(base, "home"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(homeRoot.String(), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, envName := range []string{"HC_SOCKET", "HC_TERMINAL_SOCKET"} {
		for _, tc := range []struct {
			name string
			val  string
		}{
			{"leading_space", " /private/tmp/mgh-test/s.sock"},
			{"trailing_space", "/private/tmp/mgh-test/s.sock "},
			{"relative", "relative/s.sock"},
			{"unclean_dotdot", "/private/tmp/a/../b/s.sock"},
			{"non_printable", "/private/tmp/bad\nline/s.sock"},
		} {
			t.Run(envName+"/"+tc.name, func(t *testing.T) {
				t.Setenv("HC_SOCKET", "")
				t.Setenv("HC_TERMINAL_SOCKET", "")
				t.Setenv(envName, tc.val)
				if _, _, err := defaultControlPlanePathsForHome(homeRoot); err == nil {
					t.Fatalf("defaultControlPlanePathsForHome accepted invalid %s=%q", envName, tc.val)
				}
			})
		}
	}

	t.Run("missing-leaf /tmp symlink expands to /private/tmp for Codex and default paths", func(t *testing.T) {
		t.Setenv("HC_SOCKET", "/tmp/mulgae-missing-cp-dir/server.sock")
		t.Setenv("HC_TERMINAL_SOCKET", "")
		roots, literals, err := defaultControlPlanePathsForHome(homeRoot)
		if err != nil {
			t.Fatalf("defaultControlPlanePathsForHome failed: %v", err)
		}
		hasRoot := func(want string) bool {
			for _, r := range roots {
				if r.String() == want {
					return true
				}
			}
			return false
		}
		hasLit := func(want string) bool {
			for _, l := range literals {
				if l.String() == want {
					return true
				}
			}
			return false
		}
		for _, wantRoot := range []string{"/tmp/mulgae-missing-cp-dir", "/private/tmp/mulgae-missing-cp-dir"} {
			if !hasRoot(wantRoot) {
				t.Fatalf("missing expected control-plane root %q in %v", wantRoot, roots)
			}
		}
		for _, wantLit := range []string{"/tmp/mulgae-missing-cp-dir/server.sock", "/private/tmp/mulgae-missing-cp-dir/server.sock"} {
			if !hasLit(wantLit) {
				t.Fatalf("missing expected control-plane literal %q in %v", wantLit, literals)
			}
		}

		// Verify Codex liveReviewArgv receives BOTH raw and canonical /private/tmp forms.
		ctx := context.Background()
		projectDir := filepath.Join(base, "codex-proj")
		for _, dir := range []string{projectDir, filepath.Join(homeRoot.String(), ".codex")} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(projectDir, "a.go"), []byte("package a\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		reviewerHome, err := OpenReviewerHome(homeRoot, []byte("guide\n"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = reviewerHome.Close() }()
		codexCred, _ := ports.NewAnchoredRoot(filepath.Join(homeRoot.String(), ".codex"))
		sourceAdapter, err := gittargetadapter.NewLiveSourceAdapter(gittargetadapter.NewExecRunner(), []ports.AnchoredRoot{codexCred})
		if err != nil {
			t.Fatal(err)
		}
		projRoot, _ := ports.NewAnchoredRoot(projectDir)
		sel, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
		src, err := sourceAdapter.OpenLiveSource(ctx, projRoot, sel)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = src.Close() }()
		execBase, err := ports.NewLiveReviewExecution(ctx, src, reviewerHome, []ports.AnchoredRoot{codexCred})
		if err != nil {
			t.Fatal(err)
		}
		codexDef := testDefinition(t, FamilyCodex, "codex_cp")
		argv, err := liveReviewArgv(codexDef, execBase, nil, false)
		if err != nil {
			t.Fatalf("liveReviewArgv(codex) error = %v", err)
		}
		joined := strings.Join(argv, " ")
		if !strings.Contains(joined, `"/private/tmp/mulgae-missing-cp-dir"="deny"`) ||
			!strings.Contains(joined, `"/tmp/mulgae-missing-cp-dir"="deny"`) {
			t.Fatalf("Codex liveReviewArgv missing canonical/raw control-plane deny: %s", joined)
		}

		// And malformed HC_SOCKET must fail closed inside liveReviewArgv.
		t.Setenv("HC_SOCKET", "relative/bad.sock")
		if _, err := liveReviewArgv(codexDef, execBase, nil, false); err == nil {
			t.Fatal("liveReviewArgv(codex) silently ignored malformed HC_SOCKET")
		}
	})

	t.Run("symlinked ~/.config and ~/.local/state expand missing-tolerantly for default control-plane roots", func(t *testing.T) {
		t.Setenv("HC_SOCKET", "")
		t.Setenv("HC_TERMINAL_SOCKET", "")
		dotfiles := filepath.Join(base, "dotfiles")
		dotfilesConfig := filepath.Join(dotfiles, "config")
		dotfilesState := filepath.Join(dotfiles, "state")
		symHome := filepath.Join(base, "sym-home")
		for _, dir := range []string{dotfilesConfig, dotfilesState, filepath.Join(symHome, ".local")} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(dotfilesConfig, filepath.Join(symHome, ".config")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(dotfilesState, filepath.Join(symHome, ".local", "state")); err != nil {
			t.Fatal(err)
		}
		symHomeRoot, err := ports.NewAnchoredRoot(symHome)
		if err != nil {
			t.Fatal(err)
		}
		roots, _, err := defaultControlPlanePathsForHome(symHomeRoot)
		if err != nil {
			t.Fatalf("defaultControlPlanePathsForHome(symlinked dotfiles) error = %v", err)
		}
		rootSet := make(map[string]bool, len(roots))
		for _, r := range roots {
			rootSet[r.String()] = true
		}
		for _, want := range []string{
			filepath.Join(symHome, ".config", "herdr-core"),
			filepath.Join(dotfilesConfig, "herdr-core"),
			filepath.Join(symHome, ".local", "state", "herdr-core"),
			filepath.Join(dotfilesState, "herdr-core"),
		} {
			if !rootSet[want] {
				t.Fatalf("missing expected default control-plane root %q in %v", want, roots)
			}
		}
	})

	t.Run("symlinked ~/.config/herdr-core -> / fails closed via validLivePolicyRoot", func(t *testing.T) {
		t.Setenv("HC_SOCKET", "")
		t.Setenv("HC_TERMINAL_SOCKET", "")
		badHome := filepath.Join(base, "bad-root-sym-home")
		if err := os.MkdirAll(filepath.Join(badHome, ".config"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/", filepath.Join(badHome, ".config", "herdr-core")); err != nil {
			t.Fatal(err)
		}
		badHomeRoot, err := ports.NewAnchoredRoot(badHome)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := defaultControlPlanePathsForHome(badHomeRoot); err == nil {
			t.Fatal("defaultControlPlanePathsForHome accepted ~/.config/herdr-core -> /")
		}
	})
}

func TestGrokKernelProbePrivateControlDirPassesBuildPaneLaunch(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	homeDir := filepath.Join(base, "home")
	neutralDir := filepath.Join(homeDir, ".mulgae", "home")
	writableDir := filepath.Join(base, "writable")
	grokCredDir := filepath.Join(homeDir, ".grok")
	for _, dir := range []string{neutralDir, writableDir, grokCredDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	rawControlDir, err := os.MkdirTemp("", "mg-probe-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(rawControlDir) })
	controlDir, err := filepath.EvalSymlinks(rawControlDir)
	if err != nil {
		t.Fatal(err)
	}
	homeRoot, _ := ports.NewAnchoredRoot(homeDir)
	neutralRoot, _ := ports.NewAnchoredRoot(neutralDir)
	writableRoot, _ := ports.NewAnchoredRoot(writableDir)
	grokCredRoot, _ := ports.NewAnchoredRoot(grokCredDir)
	controlRoot, _ := ports.NewAnchoredRoot(controlDir)

	boundary, err := ports.NewLiveReadOnlyBoundary([]ports.AnchoredRoot{neutralRoot}, []ports.AnchoredRoot{grokCredRoot}, writableRoot)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err = ports.NewLiveReadOnlyBoundaryWithControlPlane(boundary, []ports.AnchoredRoot{controlRoot}, nil)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err = ports.NewLiveReadOnlyBoundaryWithPaneTTY(boundary, homeRoot)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := filepath.EvalSymlinks("/bin/echo")
	if err != nil {
		t.Fatal(err)
	}
	packet, _ := ports.NewProviderPacketFromBytes([]byte("probe"))
	binding, _ := ports.NewTerminalProviderPacketBinding(packet)
	procReq, err := ports.NewProviderProcessRequest(executable, []string{executable}, nil, neutralRoot.String(), binding, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	procReq, err = ports.NewLiveReadOnlyProcessRequest(procReq, boundary)
	if err != nil {
		t.Fatal(err)
	}
	launchDir, err := os.Open(neutralRoot.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = launchDir.Close() }()
	procReq, err = ports.NewNeutralBoundProcessRequest(procReq, neutralRoot, launchDir)
	if err != nil {
		t.Fatal(err)
	}
	paneReq, err := ports.NewPaneLaunchRequest(procReq, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := processadapter.NewPaneLaunchBuilder().BuildPaneLaunch(context.Background(), paneReq)
	if err != nil {
		t.Fatalf("BuildPaneLaunch with 0700 os.MkdirTemp(\"\", \"mg-probe-\") failed: %v", err)
	}
	if _, statErr := os.Stat(spec.ProfileFilePath()); statErr != nil {
		t.Fatalf("compiled Seatbelt profile missing: %v", statErr)
	}
}

func TestQualificationSecurityViolationsOutrankContextCancellationAndTimeout(t *testing.T) {
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	t.Run("qualificationInterruptionFailure preserves security violations on TimedOut and Cancelled observations", func(t *testing.T) {
		secDriverErr := newTerminalDriverFailure(
			ports.ProviderExecutionStatusSecurityViolation,
			"process_security",
			domain.DiagnosticCauseProcessGroupCleanupFailed,
			domain.DiagnosticCauseProcessGroupCleanupFailed,
			errors.New("started pane residual process group"),
		)
		cleanupProcErr, err := ports.NewProcessExecutionError(
			domain.DiagnosticCauseTimedOut,
			domain.DiagnosticCauseProcessGroupCleanupFailed,
			nil, nil, errors.New("cleanup failed"),
		)
		if err != nil {
			t.Fatal(err)
		}
		promptPostErr, err := ports.NewProcessExecutionError(
			domain.DiagnosticCausePromptFilePostEndFailed,
			"", nil, nil, errors.New("prompt mutated"),
		)
		if err != nil {
			t.Fatal(err)
		}
		for _, term := range []ports.ProcessTermination{ports.ProcessTerminationTimedOut, ports.ProcessTerminationCancelled} {
			obs := testProcessObservation(t, nil, nil, term, 0)
			for _, secErr := range []error{secDriverErr, cleanupProcErr, promptPostErr} {
				if got := qualificationInterruptionFailure(obs, secErr); got != nil {
					t.Fatalf("qualificationInterruptionFailure(%s, %T) = %v, want nil (must not downgrade security failure)", term, secErr, got)
				}
			}
		}
	})

	t.Run("classifyProbeFailure preserves FailureSecurityPolicy even when ctx is cancelled", func(t *testing.T) {
		cleanupProcErr, err := ports.NewProcessExecutionError(
			domain.DiagnosticCauseTimedOut,
			domain.DiagnosticCauseProcessGroupCleanupFailed,
			nil, nil, errors.New("cleanup failed"),
		)
		if err != nil {
			t.Fatal(err)
		}
		promptPostErr, err := ports.NewProcessExecutionError(
			domain.DiagnosticCausePromptFilePostEndFailed,
			"", nil, nil, errors.New("prompt mutated"),
		)
		if err != nil {
			t.Fatal(err)
		}
		secDriverErr := newTerminalDriverFailure(
			ports.ProviderExecutionStatusSecurityViolation,
			"process_security",
			domain.DiagnosticCauseProcessGroupCleanupFailed,
			domain.DiagnosticCauseProcessGroupCleanupFailed,
			errors.New("started pane residual"),
		)
		for _, secErr := range []error{cleanupProcErr, promptPostErr, secDriverErr} {
			classified := classifyProbeFailure(cancelledCtx, FamilyGrok, secErr, nil, nil)
			var failure *domain.Failure
			if !errors.As(classified, &failure) || failure.Class() != domain.FailureSecurityPolicy {
				t.Fatalf("classifyProbeFailure(cancelledCtx, %T) = %#v (err=%v), want FailureSecurityPolicy", secErr, failure, classified)
			}
		}
	})
}

func TestRegistryObserveSpawnFailedProjectsToUnavailableProviderSpawnFailed(t *testing.T) {
	ctx := context.Background()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	nativeHomeDir := filepath.Join(base, "native-home")
	nsBaseDir := filepath.Join(base, "namespaces")
	projectDir := filepath.Join(base, "project")
	for _, dir := range []string{filepath.Join(nativeHomeDir, ".grok"), nsBaseDir, projectDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(nativeHomeDir, ".grok", "auth.json"), []byte(`{"token":"test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := RuntimeSafetyPolicyForFamily(CredentialSourceGrok)
	if err != nil {
		t.Fatal(err)
	}
	nsBase, err := NewNamespaceFactory(nsBaseDir)
	if err != nil {
		t.Fatal(err)
	}
	nsFactory, err := NewCredentialProjectingNamespaceFactoryWithPolicies(
		nsBase, nativeHomeDir,
		map[string]CredentialSourceFamily{"grok_spawn": CredentialSourceGrok},
		map[string]RuntimeSafetyPolicy{"grok_spawn": policy},
	)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := filepath.EvalSymlinks("/bin/echo")
	if err != nil {
		t.Fatal(err)
	}
	defPort, err := (RuntimeBuilder{}).BuildProductionRuntime(ports.ProviderRuntimeSpec{
		Family: FamilyGrok, Instance: "grok_spawn", Executable: executable,
		ExecutableSHA256: "sha256:" + strings.Repeat("1", 64),
		Launcher:         executable, LauncherSHA256: "sha256:" + strings.Repeat("1", 64),
		ProfileID: "grok_spawn", ProfileGeneration: "spawn-gen",
		RuntimeSafetyPolicyIdentity: policy.Identity(),
		BaseArgv:                    []string{executable},
		TransportChannel:            ports.ProviderPacketChannelTerminal,
		TransportArgvIndex:          -1,
		WorkingDirectory:            "/private/var/empty",
		Timeout:                     2 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	def := defPort.(RuntimeDefinition)

	termRunner := &fakeTerminalSessionRunner{identity: defaultFakeTerminalIdentity(t)}
	termRunner.runFunc = func(_ context.Context, _ ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
		return ports.TerminalExecutionObservation{}, func() error {
			procErr, buildErr := ports.NewProcessExecutionError(domain.DiagnosticCauseProviderSpawnFailed, "", nil, nil, errors.New("herdr spawn failed"))
			if buildErr != nil {
				t.Fatal(buildErr)
			}
			return procErr
		}()
	}
	registry, err := NewProductionRegistryWithTerminalRunner(ctx, &neutralVersionProbeRunner{}, termRunner, nsFactory, testSpawnVerifier{}, def)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = registry.Close(ctx) }()

	nativeHomeRoot, _ := ports.NewAnchoredRoot(nativeHomeDir)
	reviewerHome, err := OpenReviewerHome(nativeHomeRoot, []byte("guide\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reviewerHome.Close() }()
	grokCredRoot, _ := ports.NewAnchoredRoot(filepath.Join(nativeHomeDir, ".grok"))
	sourceAdapter, err := gittargetadapter.NewLiveSourceAdapter(gittargetadapter.NewExecRunner(), []ports.AnchoredRoot{grokCredRoot})
	if err != nil {
		t.Fatal(err)
	}
	projRoot, _ := ports.NewAnchoredRoot(projectDir)
	sel, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	src, err := sourceAdapter.OpenLiveSource(ctx, projRoot, sel)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	execution, err := ports.NewLiveReviewExecution(ctx, src, reviewerHome, []ports.AnchoredRoot{grokCredRoot})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := ports.NewProviderInvocationInLiveSource(testInvocation(t, "grok_spawn"), execution)
	if err != nil {
		t.Fatal(err)
	}
	obs, obsErr := registry.Observe(ctx, inv)
	if obsErr != nil {
		t.Fatalf("Observe(spawn failed) returned raw error %v, want partial unavailable observation", obsErr)
	}
	if obs.Status() != ports.ProviderExecutionStatusUnavailable ||
		obs.DiagnosticCode() != "provider_spawn_failed" ||
		obs.PrimaryCause() != domain.DiagnosticCauseProviderSpawnFailed {
		t.Fatalf("Observe(spawn failed) = status:%q diag:%q cause:%q, want unavailable/provider_spawn_failed/provider_spawn_failed",
			obs.Status(), obs.DiagnosticCode(), obs.PrimaryCause())
	}
}

type fakeCredentialFileInfo struct {
	name string
	size int64
	mode fs.FileMode
	stat syscall.Stat_t
}

func (f fakeCredentialFileInfo) Name() string       { return f.name }
func (f fakeCredentialFileInfo) Size() int64        { return f.size }
func (f fakeCredentialFileInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeCredentialFileInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (f fakeCredentialFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeCredentialFileInfo) Sys() any           { return &f.stat }

func TestSafePrivateSingleLinkCredentialSourceRejectsForeignUIDHardlinkAndEmpty(t *testing.T) {
	euid := uint32(os.Geteuid())
	valid := fakeCredentialFileInfo{
		name: "auth.json",
		size: 16,
		mode: 0o600,
		stat: syscall.Stat_t{Nlink: 1, Uid: euid},
	}
	if !safePrivateSingleLinkCredentialSource(valid) {
		t.Fatal("safePrivateSingleLinkCredentialSource rejected valid private single-link file")
	}
	foreign := valid
	foreign.stat.Uid = euid + 1
	if safePrivateSingleLinkCredentialSource(foreign) {
		t.Fatal("safePrivateSingleLinkCredentialSource accepted foreign-owned credential file")
	}
	hardlinked := valid
	hardlinked.stat.Nlink = 2
	if safePrivateSingleLinkCredentialSource(hardlinked) {
		t.Fatal("safePrivateSingleLinkCredentialSource accepted hardlinked credential file")
	}
	empty := valid
	empty.size = 0
	if safePrivateSingleLinkCredentialSource(empty) {
		t.Fatal("safePrivateSingleLinkCredentialSource accepted 0-byte credential file")
	}
}
