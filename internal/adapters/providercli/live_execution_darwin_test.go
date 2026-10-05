//go:build darwin && arm64

package providercli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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
			authority, err := newGrokLiveReadAuthority(ctx, execution)
			if err != nil {
				t.Fatal(err)
			}
			t.Run("partial-message-failure", func(t *testing.T) {
				for _, partial := range []bool{false, true} {
					name := "before-message"
					if partial {
						name = "after-partial-message"
					}
					t.Run(name, func(t *testing.T) {
						session := mustGrokSession(t, protocolPurposeLiveReview)
						session.liveReads = authority
						lines := []string{grokInitializeResult, grokAuthResult, grokNewResult}
						if partial {
							lines = append(lines, `{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"session-script","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"partial assistant report"}}}}`)
						}
						lines = append(lines, `{"jsonrpc":"2.0","id":"denied-tool","method":"session/request_permission","params":{"sessionId":"session-script","toolCall":{"toolCallId":"denied-tool","kind":"execute","rawInput":{"variant":"Bash","command":"cat /not-in-plan"}},"options":[{"kind":"allow_once","optionId":"allow"}]}}`)
						driveErr, _ := driveGrokScripted(t, session, lines...)
						if driveErr == nil || grokCause(t, driveErr) != domain.DiagnosticCausePermissionDenied {
							t.Fatalf("permission failure = %v", driveErr)
						}
						receipt, ok := session.SessionObservation()
						if !ok || receipt.Terminal() != ports.ProviderSessionFailed || !receipt.Input().CreateAccepted || !receipt.Input().SendAccepted || receipt.Input().TurnObserved || receipt.Input().MessagesReceived {
							t.Fatalf("incomplete failed session receipt: present=%t receipt=%#v", ok, receipt.Input())
						}
						invocation := testInvocation(t, "grok-failed-read")
						observed, err := ports.NewFailedProtocolProviderExecutionObservationWithCause(ports.ProviderExecutionStatusAuthentication, invocation, protocolTeardownObservation(t, []byte("protocol transcript")), receipt, "provider_permission_denied", domain.DiagnosticCausePermissionDenied, "")
						if err != nil || observed.Invocation().InputIdentity() != invocation.InputIdentity() || observed.Status() != ports.ProviderExecutionStatusAuthentication || observed.PrimaryCause() != domain.DiagnosticCausePermissionDenied {
							t.Fatalf("permission failure lost invocation or cause: status=%s cause=%s error=%v", observed.Status(), observed.PrimaryCause(), err)
						}
						if _, ok := observed.Result(); ok {
							t.Fatal("partial failed assistant message became a successful result")
						}
					})
				}
			})
			for _, variant := range []string{"ReadFile", "Bash"} {
				state := grokACPConversation{purpose: protocolPurposeLiveReview, liveReads: authority, sessionID: "fixture-session", sessionCreated: true, toolVariants: make(map[string]bool)}
				params, err := json.Marshal(map[string]any{"sessionId": state.sessionID, "update": map[string]any{"sessionUpdate": grokACPToolCall, "toolCallId": "fixture-tool", "rawInput": map[string]string{"variant": variant, "target_file": "/partial", "command": "git --no"}}})
				if err != nil {
					t.Fatal(err)
				}
				if err := state.handleNotification(ctx, nil, grokACPMessage{Method: grokACPSessionUpdateMethod, Params: params}); err != nil {
					t.Fatalf("partial tool notification rejected: %v", err)
				}
				params, err = json.Marshal(map[string]any{"sessionId": state.sessionID, "toolCall": map[string]any{"toolCallId": "fixture-tool", "kind": "read", "rawInput": map[string]string{"variant": variant}}})
				if err != nil {
					t.Fatal(err)
				}
				if err := state.handleLiveReadPermission(ctx, nil, grokACPMessage{Method: grokACPRequestPermission, Params: params}); err == nil {
					t.Fatal("partial notification authorized an incomplete permission request")
				}
			}
			for _, variant := range []string{"Write", "MCPTool", "Unknown"} {
				state := grokACPConversation{purpose: protocolPurposeLiveReview, liveReads: authority, sessionID: "fixture-session", sessionCreated: true, toolVariants: make(map[string]bool)}
				params, err := json.Marshal(map[string]any{"sessionId": state.sessionID, "update": map[string]any{"sessionUpdate": grokACPToolCallUpdate, "toolCallId": "fixture-tool", "rawInput": map[string]string{"variant": variant}}})
				if err != nil {
					t.Fatal(err)
				}
				if err := state.handleNotification(ctx, nil, grokACPMessage{Method: grokACPSessionUpdateMethod, Params: params}); err == nil {
					t.Fatalf("unexpected live notification variant %s admitted", variant)
				}
			}
			// Only a complete, correlated permission request may grant one read.
			variant, kind, path, command := "ReadFile", "read", filepath.Join(project, "target 'quoted'.txt"), ""
			if scope != domain.LiveSourceWorkspace {
				variant, kind, path, command = "Bash", "execute", "", execution.Reads()[0].GitCommand()
			}
			for _, scenario := range []string{"completed", "failed", "outside-plan", "outside-plan-completed", "missing-input", "missing-tool-id", "unfinished", "reopened", "variant-change", "worktree-substitute"} {
				t.Run("terminal-"+scenario, func(t *testing.T) {
					state := grokACPConversation{purpose: protocolPurposeLiveReview, liveReads: authority, sessionID: "fixture-session", sessionCreated: true, promptSent: true, toolVariants: make(map[string]bool), messageReceived: true}
					toolID, file, operand := "fixture-tool", path, command
					if scenario == "missing-tool-id" {
						toolID = ""
					}
					if strings.HasPrefix(scenario, "outside-plan") {
						file, operand = filepath.Join(credentials, "auth.txt"), command+"; cat secret"
					}
					if scenario == "missing-input" {
						file, operand = "", ""
					}
					inputVariant, inputKind := variant, kind
					if scenario == "worktree-substitute" {
						inputVariant, inputKind, file = "ReadFile", "read", filepath.Join(project, "target 'quoted'.txt")
					}
					update := func(status string, input bool) error {
						values := map[string]any{"sessionUpdate": grokACPToolCallUpdate, "toolCallId": toolID, "status": status}
						if input {
							values["kind"] = inputKind
							values["rawInput"] = map[string]string{"variant": inputVariant, "target_file": file, "command": operand}
						}
						params, err := json.Marshal(map[string]any{"sessionId": state.sessionID, "update": values})
						if err != nil {
							t.Fatal(err)
						}
						return state.handleNotification(ctx, nil, grokACPMessage{Method: grokACPSessionUpdateMethod, Params: params})
					}
					partial := map[string]string{"target_file": file}
					if scope != domain.LiveSourceWorkspace {
						partial = map[string]string{"command": operand}
					}
					params, err := json.Marshal(map[string]any{"sessionId": state.sessionID, "update": map[string]any{"sessionUpdate": grokACPToolCall, "toolCallId": toolID, "rawInput": partial}})
					if err != nil {
						t.Fatal(err)
					}
					err = state.handleNotification(ctx, nil, grokACPMessage{Method: grokACPSessionUpdateMethod, Params: params})
					if err == nil {
						err = update("pending", true)
					}
					if err == nil {
						if scenario == "unfinished" {
							_, err = state.handle(ctx, &scriptedCodexExchange{}, grokACPMessage{ID: json.RawMessage(`"mulgae-session-prompt"`), Result: json.RawMessage(`{"stopReason":"end_turn"}`)})
						} else {
							status := "completed"
							if scenario == "failed" || scenario == "outside-plan" {
								status = "failed"
							}
							if scenario == "variant-change" {
								inputVariant = "Bash"
								if variant == "Bash" {
									inputVariant = "ReadFile"
								}
							}
							err = update(status, scenario == "variant-change")
							if err == nil && scenario == "reopened" {
								err = update("pending", false)
							}
						}
					}
					if scenario == "completed" || scenario == "failed" || (scenario == "worktree-substitute" && scope == domain.LiveSourceWorkspace) {
						if err == nil {
							exchange := &scriptedCodexExchange{}
							_, err = state.handle(ctx, exchange, grokACPMessage{ID: json.RawMessage(`"mulgae-session-prompt"`), Result: json.RawMessage(`{"stopReason":"end_turn"}`)})
							if err == nil && len(exchange.sent) != 1 {
								t.Fatal("complete planned read did not reach native close")
							}
						}
						if err != nil {
							t.Fatalf("exact planned native read rejected: %v", err)
						}
					} else if err == nil || grokCause(t, err) != domain.DiagnosticCausePermissionDenied {
						t.Fatalf("unverified terminal tool admitted: %v", err)
					}
					if scenario == "variant-change" && !strings.Contains(err.Error(), "live ACP tool variant changed") {
						t.Fatalf("variant change lost its correlated rejection: %v", err)
					}
				})
			}
			for _, status := range []string{"pending", "in_progress", "", "completed", "failed"} {
				name := status
				if name == "" {
					name = "statusless"
				}
				t.Run("post-prompt-"+name, func(t *testing.T) {
					state := grokACPConversation{purpose: protocolPurposeLiveReview, liveReads: authority, sessionID: "fixture-session", sessionCreated: true, promptSent: true, messageReceived: true, toolVariants: make(map[string]bool)}
					exchange := &scriptedCodexExchange{}
					done, err := state.handle(ctx, exchange, grokACPMessage{ID: json.RawMessage(`"mulgae-session-prompt"`), Result: json.RawMessage(`{"stopReason":"end_turn"}`)})
					if err != nil || done || !state.closeSent || len(exchange.sent) != 1 {
						t.Fatalf("prompt did not request native close: done=%t, error=%v", done, err)
					}
					params, err := json.Marshal(map[string]any{"sessionId": state.sessionID, "update": map[string]any{"sessionUpdate": grokACPToolCallUpdate, "toolCallId": "late-tool", "status": status, "kind": kind, "rawInput": map[string]string{"variant": variant, "target_file": path, "command": command}}})
					if err != nil {
						t.Fatal(err)
					}
					if err := state.handleNotification(ctx, exchange, grokACPMessage{Method: grokACPSessionUpdateMethod, Params: params}); err != nil {
						t.Fatalf("correlated late tool update rejected: %v", err)
					}
					done, err = state.handle(ctx, exchange, grokACPMessage{ID: json.RawMessage(`"mulgae-session-close"`), Result: json.RawMessage(`{}`)})
					if status == "completed" || status == "failed" {
						if err != nil || !done || !state.closeAccepted {
							t.Fatalf("complete late planned read rejected: done=%t, error=%v", done, err)
						}
					} else if err == nil || !done || state.closeAccepted || grokCause(t, err) != domain.DiagnosticCausePermissionDenied || !strings.Contains(err.Error(), "live ACP tool completion is missing") {
						t.Fatalf("incomplete post-prompt tool retained report acceptance: done=%t, accepted=%t, error=%v", done, state.closeAccepted, err)
					}
				})
			}
			for _, scenario := range []string{"admitted", "wrong-session", "missing-tool-id", "missing-allow-once", "outside-plan", "unexpected-method", "obsolete-field"} {
				session, toolID, optionKind, operand, method := "fixture-session", "fixture-tool", "allow_once", command, grokACPRequestPermission
				file := path
				switch scenario {
				case "wrong-session":
					session = "other-session"
				case "missing-tool-id":
					toolID = ""
				case "missing-allow-once":
					optionKind = "allow_always"
				case "outside-plan":
					file, operand = filepath.Join(credentials, "auth.txt"), command+"; touch injected"
				case "unexpected-method":
					method = "session/arbitrary"
				}
				inputKind := kind
				rawInput := map[string]string{"variant": variant, "target_file": file, "command": operand}
				if scenario == "obsolete-field" {
					inputKind = "read"
					rawInput = map[string]string{"variant": "ReadFile", "file_path": filepath.Join(project, "target 'quoted'.txt")}
				}
				params, err := json.Marshal(map[string]any{"sessionId": session, "toolCall": map[string]any{"toolCallId": toolID, "kind": inputKind, "rawInput": rawInput}, "options": []map[string]string{{"optionId": "once-17", "kind": optionKind}}})
				if err != nil {
					t.Fatal(err)
				}
				state := grokACPConversation{purpose: protocolPurposeLiveReview, liveReads: authority, sessionID: "fixture-session"}
				exchange := &scriptedCodexExchange{}
				err = state.handleLiveReadPermission(ctx, exchange, grokACPMessage{Method: method, ID: json.RawMessage("17"), Params: params})
				if scenario != "admitted" {
					if err == nil || len(exchange.sent) != 0 {
						t.Fatalf("%s permission granted: %v, %s", scenario, err, exchange.sent)
					}
					if scenario == "obsolete-field" && grokCause(t, err) != domain.DiagnosticCausePermissionDenied {
						t.Fatalf("obsolete ReadFile field lost typed denial: %v", err)
					}
					continue
				}
				if err != nil || len(exchange.sent) != 1 {
					t.Fatalf("complete read permission: %v, %s", err, exchange.sent)
				}
				var response struct {
					ID     int `json:"id"`
					Result struct {
						Outcome struct {
							Outcome  string `json:"outcome"`
							OptionID string `json:"optionId"`
						} `json:"outcome"`
					} `json:"result"`
				}
				if json.Unmarshal(exchange.sent[0], &response) != nil || response.ID != 17 || response.Result.Outcome.Outcome != "selected" || response.Result.Outcome.OptionID != "once-17" {
					t.Fatalf("permission response lost one-shot identity: %s", exchange.sent[0])
				}
			}
			if scope == domain.LiveSourceWorkspace {
				if err := authority.allow(ctx, "read", "ReadFile", filepath.Join(project, "target 'quoted'.txt"), ""); err != nil {
					t.Fatal(err)
				}
			} else {
				for _, read := range execution.Reads() {
					if err := authority.allow(ctx, "execute", "Bash", "", read.GitCommand()); err != nil {
						t.Fatal(err)
					}
					if err := authority.allow(ctx, "execute", "Bash", "", read.GitCommand()+"; touch injected"); err == nil {
						t.Fatal("shell suffix admitted")
					}
				}
				if err := authority.allow(ctx, "read", "ReadFile", filepath.Join(project, "target 'quoted'.txt"), ""); err == nil {
					t.Fatal("Git selector admitted worktree substitute")
				}
			}
			for _, test := range []struct{ kind, variant, path, command string }{
				{"read", "ReadFile", filepath.Join(credentials, "auth.txt"), ""},
				{"read", "ReadFile", filepath.Join(project, ".git", "config"), ""},
				{"read", "ReadFile", filepath.Join(home.Root().String(), "AGENTS.md"), ""},
				{"edit", "Write", filepath.Join(project, "target 'quoted'.txt"), ""},
				{"execute", "Bash", "", "git update-ref refs/heads/probe HEAD"},
				{"execute", "Bash", "", "git config user.name changed"},
				{"execute", "Bash", "", "git show HEAD:target.txt"},
			} {
				if err := authority.allow(ctx, test.kind, test.variant, test.path, test.command); err == nil {
					t.Fatalf("unplanned native operation admitted: %+v", test)
				}
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
			if execution.Revalidate(ctx) == nil || authority.allow(ctx, "execute", "Bash", "", "git show HEAD:target.txt") == nil {
				t.Fatal("replaced source retained execution/read authority")
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
