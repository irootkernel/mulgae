//go:build darwin && arm64

package providercli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	gittargetadapter "github.com/irootkernel/mulgae/internal/adapters/gittarget"
	processadapter "github.com/irootkernel/mulgae/internal/adapters/process"
	runtimeadapter "github.com/irootkernel/mulgae/internal/adapters/runtime"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestLiveGitEnvironmentBlocksNativeRepositoryHelpers(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "executed.txt")
	helper := filepath.Join(root, "helper.sh")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf called > '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	run := func(environment []string, args ...string) error {
		t.Helper()
		command := exec.Command("/usr/bin/git", append([]string{"-C", root}, args...)...)
		command.Env = environment
		return command.Run()
	}
	fixtureEnvironment := []string{"PATH=/usr/bin:/bin", "HOME=/var/empty", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"}
	for _, args := range [][]string{{"init", "--quiet"}, {"config", "core.fsmonitor", helper}, {"config", "core.hooksPath", root}} {
		if err := run(fixtureEnvironment, args...); err != nil {
			t.Fatal(err)
		}
	}
	project, _ := ports.NewAnchoredRoot(root)
	gitDirectory, _ := ports.NewAnchoredRoot(filepath.Join(root, ".git"))
	variables, err := liveGitEnvironment(ports.ProjectBindingObservation{Root: project, GitDirectory: gitDirectory})
	if err != nil {
		t.Fatal(err)
	}
	environment := []string{"HOME=/var/empty"}
	for _, variable := range variables {
		environment = append(environment, variable.Name()+"="+variable.Value())
	}
	if err := os.WriteFile(filepath.Join(root, "target.txt"), []byte("before\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(environment, "add", "target.txt"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "target.txt"), []byte("after\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(environment, "--no-pager", "diff"); err != nil {
		t.Fatal(err)
	}
	if err := run(environment, "ls-remote", "ext::"+helper); err == nil {
		t.Fatal("provider Git admitted an external transport helper")
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatal("provider Git executed a repository-selected helper")
	}
}

func TestLiveExecutionGuidePlanAndClosedGrokPermissions(t *testing.T) {
	for _, scope := range []domain.LiveSourceScope{domain.LiveSourceWorkspace, domain.LiveSourceStage, domain.LiveSourceHead, domain.LiveSourceCommit, domain.LiveSourceDiff} {
		t.Run(string(scope), func(t *testing.T) {
			ctx := context.Background()
			root := reviewerHomeTestRoot(t)
			project := filepath.Join(root.String(), "project")
			operator := filepath.Join(root.String(), "operator")
			credentials := filepath.Join(project, "operator-secrets")
			for _, path := range []string{project, operator, credentials} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			write := func(path, value string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(value), 0600); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(project, "target 'quoted'.txt"), "committed")
			write(filepath.Join(credentials, "auth.txt"), "SECRET")
			git := func(args ...string) {
				t.Helper()
				command := exec.Command("/usr/bin/git", append([]string{"-C", project}, args...)...)
				command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/var/empty", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"}
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatalf("fixture Git: %v (%s)", err, output)
				}
			}
			git("init", "--quiet")
			git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", "Initial")
			git("add", "target 'quoted'.txt")
			git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Baseline")
			write(filepath.Join(project, "target 'quoted'.txt"), "index")
			git("add", "target 'quoted'.txt")
			write(filepath.Join(project, "target 'quoted'.txt"), "worktree")
			operatorRoot, _ := ports.NewAnchoredRoot(operator)
			guide := []byte(strings.Repeat("shared guide line\n", 65536))
			home, err := OpenReviewerHome(operatorRoot, guide)
			if err != nil {
				t.Fatal(err)
			}
			defer home.Close()
			credentialRoot, _ := ports.NewAnchoredRoot(credentials)
			adapter, err := gittargetadapter.NewLiveSourceAdapter(gittargetadapter.NewExecRunner(), []ports.AnchoredRoot{credentialRoot})
			if err != nil {
				t.Fatal(err)
			}
			projectRoot, _ := ports.NewAnchoredRoot(project)
			operand := ""
			if scope == domain.LiveSourceCommit {
				operand = "HEAD"
			} else if scope == domain.LiveSourceDiff {
				operand = "HEAD~1..HEAD"
			}
			selector, _ := ports.NewLiveSourceSelector(scope, operand)
			source, err := adapter.OpenLiveSource(ctx, projectRoot, selector)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			execution, err := ports.NewLiveReviewExecution(ctx, source, home, []ports.AnchoredRoot{credentialRoot})
			if err != nil {
				t.Fatal(err)
			}
			// Verify Grok terminal profile enforces closed purpose-scoped tools
			// and B-1 Bash gate strictly on index/commit scopes while workspace
			// review and extraction remain strictly shell-free.
			profile := grokTerminalProfile{}
			wantBash := scope != domain.LiveSourceWorkspace
			wantReviewTools := grokToolsWorkspaceReview
			if wantBash {
				wantReviewTools = grokToolsGitReview
			}
			if got := grokReviewNeedsBashGate(scope); got != wantBash {
				t.Fatalf("scope %s grokReviewNeedsBashGate = %t, want %t", scope, got, wantBash)
			}
			if got := grokTerminalTools(terminalPurposeReview, scope, true); got != wantReviewTools {
				t.Fatalf("scope %s review --tools = %q, want %q", scope, got, wantReviewTools)
			}
			if got := grokTerminalTools(terminalPurposeExtraction, scope, true); got != grokToolsPromptBound {
				t.Fatalf("scope %s extraction --tools = %q, want %q", scope, got, grokToolsPromptBound)
			}
			def := RuntimeDefinition{executable: "/usr/local/bin/grok"}
			inv := terminalProfileInvocation{
				Definition:   def,
				Purpose:      terminalPurposeReview,
				LiveScope:    scope,
				HasLiveScope: true,
				NeutralCWD:   home.Root(),
				NativeHome:   operatorRoot,
				SourceRoot:   projectRoot,
			}
			argv, err := profile.BuildArgv(inv)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(argv, "--trust") {
				t.Fatalf("scope %s argv %q missing exact --trust flag", scope, argv)
			}
			joined := strings.Join(argv, " ")
			for _, required := range []string{
				"--permission-mode bypassPermissions",
				"--trust",
				"--no-alt-screen",
				"--deny MCPTool",
				"--tools " + wantReviewTools,
				"--cwd " + home.Root().String(),
			} {
				if !strings.Contains(joined, required) {
					t.Fatalf("scope %s argv %q missing %q", scope, joined, required)
				}
			}
			writableRoot, err := ports.NewAnchoredRoot(filepath.Join(root.String(), "writable"))
			if err != nil {
				t.Fatal(err)
			}
			baseBoundary, err := ports.NewLiveReadOnlyBoundary([]ports.AnchoredRoot{projectRoot, home.Root()}, []ports.AnchoredRoot{credentialRoot}, writableRoot)
			if err != nil {
				t.Fatal(err)
			}
			configuredBoundary, err := profile.ConfigureBoundary(baseBoundary, inv)
			if err != nil {
				t.Fatal(err)
			}
			if !configuredBoundary.PaneTTY() || configuredBoundary.OwnedPTY() || configuredBoundary.BashGate() != wantBash {
				t.Fatalf("scope %s review boundary PaneTTY=%t OwnedPTY=%t BashGate=%t, want true/false/%t", scope, configuredBoundary.PaneTTY(), configuredBoundary.OwnedPTY(), configuredBoundary.BashGate(), wantBash)
			}
			extractionInv := inv
			extractionInv.Purpose = terminalPurposeExtraction
			extractionBoundary, err := profile.ConfigureBoundary(baseBoundary, extractionInv)
			if err != nil {
				t.Fatal(err)
			}
			if !extractionBoundary.PaneTTY() || extractionBoundary.OwnedPTY() || extractionBoundary.BashGate() {
				t.Fatalf("scope %s extraction boundary PaneTTY=%t OwnedPTY=%t BashGate=%t, want true/false/false", scope, extractionBoundary.PaneTTY(), extractionBoundary.OwnedPTY(), extractionBoundary.BashGate())
			}
			catalog := builtin.NewCatalog()
			templates, err := reviewrun.LoadDefaultTemplateSet(ctx, catalog)
			if err != nil {
				t.Fatal(err)
			}
			common, err := reviewrun.LoadLiveReviewCommon(ctx, catalog)
			if err != nil {
				t.Fatal(err)
			}
			template, err := templates.ComposeLiveRootReview(ctx, common, execution, domain.RoleLogic, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(template.Bytes()), string(guide)) {
				t.Fatal("guide bytes shortened or not explicitly injected")
			}
			manifest := template.TrustedLayerManifest()
			role, _ := templates.RoleTemplate(domain.RoleLogic)
			if len(manifest) != 5 || manifest[1].ID() != "review:shared-guide" || manifest[2].ID() != "review:live-read-plan" || manifest[3].SHA256() != role.SHA256() {
				t.Fatal("trusted guide, plan or original role provenance lost")
			}
			for _, read := range execution.Reads() {
				if read.GitCommand() != "" && !strings.Contains(string(template.Bytes()), "git --no-pager show") {
					t.Fatal("native plan omitted fixed Git read")
				}
			}
			if err := os.Rename(project, project+"-replaced"); err != nil {
				t.Fatal(err)
			}
			if execution.Revalidate(ctx) == nil {
				t.Fatal("replaced source retained execution authority")
			}
		})
	}
}

func TestLiveNeutralProtocolAdmissionClosesUnconsumedDescriptor(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(map[bool]string{false: "session rejected", true: "driver unavailable"}[unavailable], func(t *testing.T) {
			root := reviewerHomeTestRoot(t)
			home, err := OpenReviewerHome(root, []byte("fixture guide"))
			if err != nil {
				t.Fatal(err)
			}
			defer home.Close()
			launch, err := home.DuplicateLaunchDirectory()
			if err != nil {
				t.Fatal(err)
			}
			defer launch.Close()
			packet, err := ports.NewProviderPacketFromBytes([]byte("fixture packet"))
			if err != nil {
				t.Fatal(err)
			}
			binding, err := ports.NewProtocolProviderPacketBinding(packet)
			if err != nil {
				t.Fatal(err)
			}
			request, err := ports.NewProviderProtocolProcessRequest("/unused-provider", []string{"/unused-provider"}, nil, home.Root().String(), binding, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			request, err = ports.NewNeutralBoundProcessRequest(request, home.Root(), launch)
			if err != nil {
				t.Fatal(err)
			}
			definition := definition{protocolDriver: zcodeProtocolDriverConstructor{}}
			if unavailable {
				definition.protocolDriver = nil
			}
			runner, err := processadapter.NewRunner(runtimeadapter.SystemClock{})
			if err != nil {
				t.Fatal(err)
			}
			registry := &Registry{runner: runner}
			if _, _, err := registry.executeProtocolProviderProcess(context.Background(), definition, packet, request, protocolInvocationPurpose("invalid"), nil, protocolSessionConfiguration{}); err == nil {
				t.Fatal("invalid protocol admission succeeded")
			}
			if _, err := launch.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("unconsumed neutral launch descriptor remains open: %v", err)
			}
		})
	}
}

func TestLiveRuntimeTempRejectsReplacementAndUnsafeDirectory(t *testing.T) {
	for _, scenario := range []string{"replacement", "symlink", "permissions", "missing"} {
		t.Run(scenario, func(t *testing.T) {
			base := reviewerHomeTestRoot(t).String()
			native := filepath.Join(base, "runtime")
			if err := os.Mkdir(native, 0700); err != nil {
				t.Fatal(err)
			}
			retained, err := os.Lstat(native)
			if err != nil {
				t.Fatal(err)
			}
			if root, err := revalidateLiveRuntimeTempRoot(native, native, retained); err != nil || root.String() != native {
				t.Fatal("valid private runtime directory rejected", err)
			}
			switch scenario {
			case "permissions":
				err = os.Chmod(native, 0755)
			case "missing":
				err = os.Remove(native)
			case "replacement", "symlink":
				err = os.Rename(native, native+"-retained")
				if err == nil && scenario == "replacement" {
					err = os.Mkdir(native, 0700)
				} else if err == nil {
					err = os.Symlink(native+"-retained", native)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := revalidateLiveRuntimeTempRoot(native, native, retained); err == nil {
				t.Fatal("unsafe native runtime directory retained launch authority")
			}
		})
	}
}

func TestLiveTerminalRevalidationDiscardsChangedSourceAndGuide(t *testing.T) {
	for _, scenario := range []string{"unchanged", "source-replaced", "guide-changed", "cancelled-unchanged", "cancelled-guide-changed"} {
		t.Run(scenario, func(t *testing.T) {
			root := reviewerHomeTestRoot(t).String()
			project, operator, credentials := filepath.Join(root, "project"), filepath.Join(root, "operator"), filepath.Join(root, "credentials")
			for _, path := range []string{project, operator, credentials} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(project, "target.txt"), []byte("fixture source"), 0600); err != nil {
				t.Fatal(err)
			}
			operatorRoot, _ := ports.NewAnchoredRoot(operator)
			home, err := OpenReviewerHome(operatorRoot, []byte("fixture guide"))
			if err != nil {
				t.Fatal(err)
			}
			defer home.Close()
			credentialRoot, _ := ports.NewAnchoredRoot(credentials)
			adapter, err := gittargetadapter.NewLiveSourceAdapter(gittargetadapter.NewExecRunner(), []ports.AnchoredRoot{credentialRoot})
			if err != nil {
				t.Fatal(err)
			}
			projectRoot, _ := ports.NewAnchoredRoot(project)
			selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			source, err := adapter.OpenLiveSource(ctx, projectRoot, selector)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			execution, err := ports.NewLiveReviewExecution(ctx, source, home, []ports.AnchoredRoot{credentialRoot})
			if err != nil {
				t.Fatal(err)
			}
			runner := &liveTerminalMutationRunner{observationRunner: observationRunner{observation: testProcessObservation(t, nil, nil, ports.ProcessTerminationExited, 0)}}
			runner.afterConversation = func() {
				switch scenario {
				case "source-replaced":
					if err := os.Rename(project, project+"-retained"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(project, 0700); err != nil {
						t.Fatal(err)
					}
				case "guide-changed", "cancelled-guide-changed":
					if err := os.WriteFile(filepath.Join(home.Root().String(), "AGENTS.md"), []byte("changed after conversation"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if strings.HasPrefix(scenario, "cancelled-") {
					cancel()
				}
			}
			registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyCodex, "codex_terminal"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if receipt, err := registry.Close(context.Background()); err != nil || !receipt.Valid() {
					t.Errorf("terminal namespace drain: %v", err)
				}
			}()
			invocation, err := ports.NewProviderInvocationInLiveSource(testInvocation(t, "codex_terminal"), execution)
			if err != nil {
				t.Fatal(err)
			}
			observation, err := registry.Observe(ctx, invocation)
			if !runner.completed || observation.Invocation().InputIdentity() != invocation.InputIdentity() {
				t.Fatalf("terminal check lost completed conversation or invocation: %v", err)
			}
			result, present := observation.Result()
			if scenario == "unchanged" || scenario == "cancelled-unchanged" {
				if err != nil || observation.Status() != ports.ProviderExecutionStatusSucceeded || !present || string(result.Stdout()) != "review result" {
					t.Fatalf("unchanged terminal binding lost report: status=%s result=%t error=%v", observation.Status(), present, err)
				}
			} else if err == nil || observation.Status() != ports.ProviderExecutionStatusSecurityViolation || observation.PrimaryCause() != domain.DiagnosticCauseWorkspaceRevalidationFailed || present {
				t.Fatalf("changed terminal binding retained report: status=%s cause=%s result=%t error=%v", observation.Status(), observation.PrimaryCause(), present, err)
			}
			if directory, _, bound := runner.request.LaunchDirectory(); !bound {
				t.Fatal("missing neutral launch authority")
			} else if _, err := directory.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("terminal observation retained launch descriptor: %v", err)
			}
		})
	}
}

type liveTerminalMutationRunner struct {
	observationRunner
	afterConversation func()
	completed         bool
}

func (runner *liveTerminalMutationRunner) Converse(ctx context.Context, request ports.ProcessRequest, driver ports.ProviderSessionDriver) (ports.ProcessObservation, error) {
	runner.request = request
	if directory, _, bound := request.LaunchDirectory(); bound {
		defer directory.Close()
	}
	if err := driver.Drive(ctx, &scriptedCodexExchange{lines: codexSuccessFrames()}); err != nil {
		return runner.observation, err
	}
	runner.completed = true
	runner.afterConversation()
	return runner.observation, nil
}
