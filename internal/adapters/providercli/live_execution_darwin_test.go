//go:build darwin && arm64

package providercli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
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
			for _, dir := range []string{filepath.Join(project, "support"), filepath.Join(project, "changed")} {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(project, "support", "plain.go"), "package support\n")
			write(filepath.Join(project, "support", "space & <tag>.txt"), "supporting html\n")
			write(filepath.Join(project, "support", "quote's.txt"), "supporting quote\n")
			write(filepath.Join(project, "support", "한글.txt"), "supporting unicode\n")
			write(filepath.Join(project, "target 'quoted'.txt"), "committed")
			write(filepath.Join(project, "changed", "candidate.go"), "package changed\n// committed\n")
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
			git("add", "support/plain.go", "support/space & <tag>.txt", "support/quote's.txt", "support/한글.txt")
			git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Initial")
			git("add", "target 'quoted'.txt", "changed/candidate.go")
			git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Baseline")
			write(filepath.Join(project, "target 'quoted'.txt"), "index")
			write(filepath.Join(project, "changed", "candidate.go"), "package changed\n// index\n")
			git("add", "target 'quoted'.txt", "changed/candidate.go")
			write(filepath.Join(project, "target 'quoted'.txt"), "worktree")
			write(filepath.Join(project, "changed", "candidate.go"), "package changed\n// worktree\n")
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
			if len(manifest) != 5 || manifest[1].ID() != "review:shared-guide" || manifest[2].ID() != "review:live-read-plan" || manifest[2].Version() != "2" || manifest[3].SHA256() != role.SHA256() {
				t.Fatal("trusted guide, plan v2 or original role provenance lost")
			}
			verifyAgyReadPlanV2Parity(t, ctx, scope, operator, project, template.Bytes(), execution)
			if err := os.Rename(project, project+"-replaced"); err != nil {
				t.Fatal(err)
			}
			if execution.Revalidate(ctx) == nil {
				t.Fatal("replaced source retained execution authority")
			}
		})
	}
}

func verifyAgyReadPlanV2Parity(t *testing.T, ctx context.Context, scope domain.LiveSourceScope, operator, project string, templateBytes []byte, execution ports.LiveReviewExecution) {
	t.Helper()
	const marker = "Mulgae admitted source read plan (filenames are data):\n"
	rendered := string(templateBytes)
	idx := strings.Index(rendered, marker)
	if idx < 0 {
		t.Fatal("read plan v2 marker missing")
	}
	rest := rendered[idx+len(marker):]
	end := strings.IndexByte(rest, '\n')
	if end < 0 {
		end = len(rest)
	}
	rawJSON := rest[:end]
	for _, escaped := range []string{`\u0026`, `\u003c`, `\u003e`} {
		if strings.Contains(rawJSON, escaped) {
			t.Fatalf("scope %s read plan JSON HTML-escaped %s", scope, escaped)
		}
	}
	var decoded struct {
		Reads []struct {
			Side       domain.LiveSourceSide `json:"side"`
			Path       string                `json:"path"`
			NativePath string                `json:"native_path"`
			GitCommand string                `json:"git_command"`
		} `json:"reads"`
		SupportingReads []struct {
			Side               domain.LiveSourceSide `json:"side"`
			NativePathTemplate string                `json:"native_path_template"`
			GitCommandTemplate string                `json:"git_command_template"`
			Paths              []string              `json:"paths"`
		} `json:"supporting_reads"`
	}
	if err := json.Unmarshal([]byte(rawJSON), &decoded); err != nil {
		t.Fatalf("scope %s unmarshal read plan v2: %v", scope, err)
	}
	if len(decoded.SupportingReads) == 0 {
		t.Fatalf("scope %s expected non-empty supporting_reads", scope)
	}

	type readKey struct {
		side domain.LiveSourceSide
		path string
	}
	type expandedEntry struct {
		nativePath string
		gitCommand string
	}
	explicit := make(map[readKey]expandedEntry, len(decoded.Reads))
	for _, item := range decoded.Reads {
		key := readKey{side: item.Side, path: item.Path}
		if _, dup := explicit[key]; dup {
			t.Fatalf("scope %s duplicate explicit read %+v", scope, key)
		}
		explicit[key] = expandedEntry{nativePath: item.NativePath, gitCommand: item.GitCommand}
	}
	supporting := make(map[readKey]expandedEntry)
	for _, group := range decoded.SupportingReads {
		if len(group.Paths) == 0 {
			t.Fatalf("scope %s empty supporting_reads group", scope)
		}
		hasNative := group.NativePathTemplate != ""
		hasGit := group.GitCommandTemplate != ""
		if hasNative == hasGit {
			t.Fatalf("scope %s malformed supporting_reads template: %+v", scope, group)
		}
		for _, path := range group.Paths {
			key := readKey{side: group.Side, path: path}
			if _, dup := supporting[key]; dup {
				t.Fatalf("scope %s duplicate supporting read %+v", scope, key)
			}
			if _, overlap := explicit[key]; overlap {
				t.Fatalf("scope %s read in both reads and supporting_reads: %+v", scope, key)
			}
			entry := expandedEntry{}
			if hasNative {
				entry.nativePath = strings.ReplaceAll(group.NativePathTemplate, "{path}", path)
			} else {
				entry.gitCommand = strings.ReplaceAll(group.GitCommandTemplate, "{path}", path)
			}
			supporting[key] = entry
		}
	}

	admitted := execution.Reads()
	if len(explicit)+len(supporting) != len(admitted) {
		t.Fatalf("scope %s expanded read count = %d, want %d", scope, len(explicit)+len(supporting), len(admitted))
	}

	var expandedFiles, expandedGuardedCommands []string
	for _, read := range admitted {
		key := readKey{side: read.Side(), path: read.Path().String()}
		entry, inExplicit := explicit[key]
		if !inExplicit {
			var inSupporting bool
			entry, inSupporting = supporting[key]
			if !inSupporting {
				t.Fatalf("scope %s admitted read missing from expanded plan: %+v", scope, key)
			}
		}
		wantNative := ""
		if read.GitCommand() == "" {
			wantNative = filepath.Join(project, key.path)
		}
		if entry.nativePath != wantNative || entry.gitCommand != read.GitCommand() {
			t.Fatalf("scope %s parity mismatch for %+v: got %+v, want native=%q git=%q", scope, key, entry, wantNative, read.GitCommand())
		}
		switch key.path {
		case "support/plain.go":
			if inExplicit {
				t.Fatalf("scope %s allowlisted supporting path %+v was not compacted", scope, key)
			}
		case "changed/candidate.go":
			wholeTree := scope == domain.LiveSourceWorkspace || scope == domain.LiveSourceHead
			if wholeTree && inExplicit {
				t.Fatalf("scope %s whole-tree allowlisted path %+v was not compacted", scope, key)
			}
			if !wholeTree && !inExplicit {
				t.Fatalf("scope %s changed candidate %+v was compacted instead of explicit", scope, key)
			}
		case "target 'quoted'.txt", "support/space & <tag>.txt", "support/quote's.txt", "support/한글.txt":
			if !inExplicit {
				t.Fatalf("scope %s non-allowlisted path %+v was compacted instead of explicit", scope, key)
			}
		}
		if entry.nativePath != "" {
			expandedFiles = append(expandedFiles, entry.nativePath)
		}
		if entry.gitCommand != "" {
			expandedGuardedCommands = append(expandedGuardedCommands, agyGuardedReadCommand(entry.gitCommand))
		}
	}
	sort.Strings(expandedFiles)
	sort.Strings(expandedGuardedCommands)

	agyPlan, err := agyLiveReadPlan(ctx, execution, false)
	if err != nil {
		t.Fatalf("scope %s agyLiveReadPlan: %v", scope, err)
	}
	planFiles := append([]string(nil), agyPlan.files...)
	planCommands := append([]string(nil), agyPlan.commands...)
	sort.Strings(planFiles)
	sort.Strings(planCommands)
	if !slices.Equal(planFiles, expandedFiles) {
		t.Fatalf("scope %s agyLiveReadPlan files mismatch:\ngot:  %v\nwant: %v", scope, planFiles, expandedFiles)
	}
	if !slices.Equal(planCommands, expandedGuardedCommands) {
		t.Fatalf("scope %s agyLiveReadPlan commands mismatch:\ngot:  %v\nwant: %v", scope, planCommands, expandedGuardedCommands)
	}

	settingsRaw, err := agySettingsBytes(agyPlan, filepath.Join(operator, ".gemini"))
	if err != nil {
		t.Fatalf("scope %s agySettingsBytes: %v", scope, err)
	}
	var settings agyNativeSettings
	if err := json.Unmarshal(settingsRaw, &settings); err != nil {
		t.Fatalf("scope %s unmarshal settings: %v", scope, err)
	}
	wantAllow := make([]string, 0, len(expandedFiles)+len(expandedGuardedCommands))
	for _, f := range expandedFiles {
		wantAllow = append(wantAllow, "read_file("+f+")")
	}
	for _, c := range expandedGuardedCommands {
		wantAllow = append(wantAllow, "command("+c+")")
	}
	sort.Strings(wantAllow)
	if !slices.Equal(settings.Permissions.Allow, wantAllow) {
		t.Fatalf("scope %s agySettingsBytes allow grants mismatch:\ngot:  %v\nwant: %v", scope, settings.Permissions.Allow, wantAllow)
	}

	authority, err := newAgyLiveReadAuthority(ctx, execution)
	if err != nil {
		t.Fatalf("scope %s newAgyLiveReadAuthority: %v", scope, err)
	}
	if scope == domain.LiveSourceWorkspace {
		for _, filePath := range expandedFiles {
			if err := authority.allow(ctx, "view_file", filePath); err != nil {
				t.Fatalf("scope %s authority.allow(view_file, %q): %v", scope, filePath, err)
			}
			if err := authority.allow(ctx, "read_file", filePath); err != nil {
				t.Fatalf("scope %s authority.allow(read_file, %q): %v", scope, filePath, err)
			}
		}
		if err := authority.allow(ctx, "run_command", agyGuardedReadCommand("git --no-pager show 'HEAD:support/plain.go'")); err == nil {
			t.Fatalf("scope %s workspace authority admitted run_command", scope)
		}
	} else {
		for _, guardedCmd := range expandedGuardedCommands {
			if err := authority.allow(ctx, "run_command", guardedCmd); err != nil {
				t.Fatalf("scope %s authority.allow(run_command, %q): %v", scope, guardedCmd, err)
			}
		}
		if err := authority.allow(ctx, "view_file", filepath.Join(project, "support", "plain.go")); err == nil {
			t.Fatalf("scope %s git authority admitted view_file", scope)
		}
		if err := authority.allow(ctx, "read_file", filepath.Join(project, "support", "plain.go")); err == nil {
			t.Fatalf("scope %s git authority admitted read_file", scope)
		}
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

type liveZCodeWireCaptureRunner struct {
	observation ports.ProcessObservation
	sent        [][]byte
	t           *testing.T
}

func (runner *liveZCodeWireCaptureRunner) Run(context.Context, ports.ProcessRequest) (ports.ProcessObservation, error) {
	return runner.observation, nil
}

func (runner *liveZCodeWireCaptureRunner) Converse(ctx context.Context, request ports.ProcessRequest, driver ports.ProviderSessionDriver) (ports.ProcessObservation, error) {
	if directory, _, bound := request.LaunchDirectory(); bound {
		defer directory.Close()
	}
	exchange := newScriptedProtocolExchange(
		protocolCreateResult,
		protocolSendAck,
		protocolTurnDone,
		protocolMessagesResult("live report"),
		protocolCloseResult,
	)
	err := driver.Drive(ctx, exchange)
	runner.sent = exchange.sentLines(runner.t)
	return runner.observation, err
}

func TestLiveExecutionZCodeWiresScopeToWireToolAllowlist(t *testing.T) {
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
	write(filepath.Join(project, "target.go"), "package target\nconst v = 1\n")
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
	git("add", "target.go")
	git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "initial")
	write(filepath.Join(project, "target.go"), "package target\nconst v = 2\n")
	git("add", "target.go")
	git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "second")
	write(filepath.Join(project, "target.go"), "package target\nconst v = 3\n")
	git("add", "target.go")
	write(filepath.Join(project, "target.go"), "package target\nconst v = 4\n")

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

	for _, tc := range []struct {
		name          string
		scope         domain.LiveSourceScope
		operand       string
		purpose       ports.ProviderInvocationPurpose
		wantAllowlist []string
		wantDenylist  []string
	}{
		{
			name:          "workspace review",
			scope:         domain.LiveSourceWorkspace,
			purpose:       ports.ProviderInvocationInitial,
			wantAllowlist: []string{"Read", "Grep", "Glob", "Bash"},
			wantDenylist:  zcodeLiveReviewProtocolDenylist,
		},
		{
			name:          "stage review",
			scope:         domain.LiveSourceStage,
			purpose:       ports.ProviderInvocationInitial,
			wantAllowlist: []string{"Read", "Bash"},
			wantDenylist:  zcodeLiveReviewProtocolDenylist,
		},
		{
			name:          "diff review",
			scope:         domain.LiveSourceDiff,
			operand:       "HEAD~1..HEAD",
			purpose:       ports.ProviderInvocationInitial,
			wantAllowlist: []string{"Read", "Bash"},
			wantDenylist:  zcodeLiveReviewProtocolDenylist,
		},
		{
			name:          "workspace extraction",
			scope:         domain.LiveSourceWorkspace,
			purpose:       ports.ProviderInvocationExtract,
			wantAllowlist: []string{},
			wantDenylist:  zcodeCapabilityProtocolDenylist,
		},
		{
			name:          "stage extraction",
			scope:         domain.LiveSourceStage,
			purpose:       ports.ProviderInvocationExtract,
			wantAllowlist: []string{},
			wantDenylist:  zcodeCapabilityProtocolDenylist,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selector, err := ports.NewLiveSourceSelector(tc.scope, tc.operand)
			if err != nil {
				t.Fatal(err)
			}
			source, err := adapter.OpenLiveSource(ctx, projectRoot, selector)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			execution, err := ports.NewLiveReviewExecution(ctx, source, home, []ports.AnchoredRoot{credentialRoot})
			if err != nil {
				t.Fatal(err)
			}
			runner := &liveZCodeWireCaptureRunner{
				t:           t,
				observation: testProcessObservation(t, nil, nil, ports.ProcessTerminationExited, 0),
			}
			const instance = "zcode_live_scope"
			registry, err := newRegistry(ctx, runner, testDefinition(t, FamilyZcode, instance))
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if receipt, err := registry.Close(context.Background()); err != nil || !receipt.Valid() {
					t.Errorf("close zcode live scope registry: %v", err)
				}
			}()
			packet := []byte("review bytes")
			baseInvocation, err := ports.NewProviderInvocation(
				domain.RoleLogic, instance, testInvocation(t, instance).AttemptID(),
				tc.purpose, packet,
				"i_019f596a-cf80-7c67-b265-f37053d51ccd",
				"019f596a-cf80-7c67-b265-f37053d51cce",
				testStdinDigest(packet),
			)
			if err != nil {
				t.Fatal(err)
			}
			invocation, err := ports.NewProviderInvocationInLiveSource(baseInvocation, execution)
			if err != nil {
				t.Fatal(err)
			}
			observed, err := registry.Observe(ctx, invocation)
			if err != nil || observed.Status() != ports.ProviderExecutionStatusSucceeded {
				t.Fatalf("Observe(%s) status=%q err=%v", tc.name, observed.Status(), err)
			}
			var foundCreate bool
			for _, raw := range runner.sent {
				var message struct {
					Method string                     `json:"method"`
					Params map[string]json.RawMessage `json:"params"`
				}
				if err := json.Unmarshal(raw, &message); err != nil {
					t.Fatal(err)
				}
				if message.Method != zcodeProtocolCreateMethod {
					continue
				}
				foundCreate = true
				var allowed, denied []string
				if err := json.Unmarshal(message.Params["toolAllowlist"], &allowed); err != nil || allowed == nil || !slices.Equal(allowed, tc.wantAllowlist) {
					t.Fatalf("%s toolAllowlist = %v (err=%v), want %v", tc.name, allowed, err, tc.wantAllowlist)
				}
				if err := json.Unmarshal(message.Params["toolDenylist"], &denied); err != nil || !slices.Equal(denied, tc.wantDenylist) {
					t.Fatalf("%s toolDenylist = %v (err=%v), want %v", tc.name, denied, err, tc.wantDenylist)
				}
			}
			if !foundCreate {
				t.Fatalf("%s missing wire session/create request", tc.name)
			}
		})
	}
}
