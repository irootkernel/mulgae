//go:build darwin && arm64 && vm_qualification

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The retained v0.1.26 binary uses the historical app-server interface.
func priorZCodeAppPaths(root string) (string, string, string) {
	bundle := filepath.Join(root, "ZCode.app")
	return bundle,
		filepath.Join(bundle, "Contents", "MacOS", "ZCode"),
		filepath.Join(bundle, "Contents", "Resources", "glm", "zcode.cjs")
}

func buildPriorZCodeWithReport(t *testing.T, root, binary, launcher, logPath, mode, barrier, reportBody string) {
	t.Helper()
	startFakeZCodeObserver(t, logPath, barrier)
	mustWriteTestFile(t, launcher, []byte("// offline fake ZCode launcher\n"))
	mustWriteTestFile(t, filepath.Join(filepath.Dir(launcher), "..", "config", "provider", "zcode-builtin.json"), []byte(`{"schemaVersion":1,"revision":30,"config":{"providerConfigRules":{"providerRules":[{"providerId":"account:zai-individual-coding-plan","config":{"builtinModelIds":["GLM-5.3","GLM-5.3-Flash"],"access":{"type":"zhipu-account","mode":"individual-coding-plan","accountType":"zai"}}}]}}}
`))
	mustWriteTestFile(t, filepath.Join(filepath.Dir(filepath.Dir(binary)), "Info.plist"), []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>3.12.3</string></dict></plist>
`))
	source := filepath.Join(t.TempDir(), "main.go")
	program := `package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
)

type observation struct {
	Argv          []string ` + "`json:\"argv\"`" + `
	CWD           string   ` + "`json:\"cwd\"`" + `
	Prompt        string   ` + "`json:\"prompt\"`" + `
	Destination   string   ` + "`json:\"destination,omitempty\"`" + `
	ToolAllowlist []string ` + "`json:\"tool_allowlist\"`" + `
}

const barrierDirectory = __FAKE_ZCODE_BARRIER__
const requestRuntimeAuth = __FAKE_ZCODE_RUNTIME_AUTH__

var roleGuide = regexp.MustCompile("Mulgae ROOT REVIEW ROLE GUIDE/[0-9]+: ([A-Z]+)")

func main() {
	argv := append([]string(nil), os.Args[1:]...)
	if len(argv) == 2 && argv[1] == "--version" {
		fmt.Println("22.14.0")
		return
	}
	if len(argv) != 3 || argv[1] != "app-server" || argv[2] != "--stdio" {
		panic("non-canonical ZCode invocation")
	}
	serve(argv)
}

// serve speaks the ZCode app-server protocol on stdio: one session per
// process, the packet as the single turn's content, and assistant text or
// controlled qualification proof produced before turn completion.
func serve(argv []string) {
	sessionID := "sess_fake"
	var prompt, mode, denylist, proof string
	var allowlist []string
	capability, accountConfigured, authAccepted, modelSelected := false, false, !requestRuntimeAuth, false
	stdout := bufio.NewWriter(os.Stdout)
	defer stdout.Flush()
	reply := func(id json.RawMessage, result any) {
		payload, err := json.Marshal(map[string]any{"id": id, "result": result})
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(stdout, string(payload))
		stdout.Flush()
	}
	notifyTurn := func(kind string) {
		payload, err := json.Marshal(map[string]any{
			"method": "computer-use/operation-event",
			"params": map[string]any{"kind": kind, "turnId": "turn_fake", "sessionId": sessionID},
		})
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(stdout, string(payload))
		stdout.Flush()
	}
	serverRequest := func(id, method string, params any) {
		payload, err := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(stdout, string(payload))
		stdout.Flush()
	}
	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		var message struct {
			ID     json.RawMessage ` + "`json:\"id\"`" + `
			Method string          ` + "`json:\"method\"`" + `
			Params json.RawMessage ` + "`json:\"params\"`" + `
		}
		if json.Unmarshal([]byte(line), &message) != nil {
			panic("unparseable protocol message")
		}
		if message.Method == "" {
			var response struct {
				ID string ` + "`json:\"id\"`" + `
				Result struct {
					HeadersApplied bool ` + "`json:\"headersApplied\"`" + `
					RequestAuth struct { APIKey string ` + "`json:\"apiKey\"`" + ` } ` + "`json:\"requestAuth\"`" + `
				} ` + "`json:\"result\"`" + `
			}
			if json.Unmarshal([]byte(line), &response) != nil {
				panic("unparseable protocol response")
			}
			if response.ID == "server-auth" {
				if !response.Result.HeadersApplied || response.Result.RequestAuth.APIKey != "fake-zcode-api-key" {
					panic("invalid ZCode runtime auth response")
				}
				authAccepted = true
			}
			continue
		}
		switch message.Method {
		case "provider/updateAccountConfig":
			var params struct {
				Revision string ` + "`json:\"revision\"`" + `
				States map[string]struct { Current bool ` + "`json:\"current\"`" + ` } ` + "`json:\"states\"`" + `
			}
			if json.Unmarshal(message.Params, &params) != nil || params.Revision == "" || !params.States["account:zai-individual-coding-plan"].Current {
				panic("non-canonical ZCode account configuration")
			}
			accountConfigured = true
			reply(message.ID, map[string]any{"receivedRevision": params.Revision, "providerCount": 1})
		case "session/create":
			var params struct {
				Mode         string   ` + "`json:\"mode\"`" + `
				ToolDenylist []string ` + "`json:\"toolDenylist\"`" + `
				ToolAllowlist []string ` + "`json:\"toolAllowlist\"`" + `
			}
			if json.Unmarshal(message.Params, &params) != nil || params.Mode == "" || len(params.ToolDenylist) == 0 || !accountConfigured {
				panic("non-canonical ZCode session create")
			}
			mode = params.Mode
			denylist = strings.Join(params.ToolDenylist, ",")
			allowlist = params.ToolAllowlist
			modelSelected = true
			serverRequest("server-1", "session/requestRuntimePreferences", map[string]any{
				"sessionId": sessionID,
				"scope":     "runtime-materialization",
			})
			if requestRuntimeAuth {
				serverRequest("server-auth", "interaction/requestProviderRuntimeHeaders", map[string]any{
					"providerId": "account:zai-individual-coding-plan",
					"accountAccess": map[string]any{"type": "zhipu-account", "mode": "individual-coding-plan", "accountType": "zai"},
				})
			}
			reply(message.ID, map[string]any{
				"session": map[string]any{"sessionId": sessionID},
				"settings": map[string]any{"model": map[string]any{"available": []any{
					map[string]any{"ref": map[string]any{"providerId": "account:zai-individual-coding-plan", "modelId": "GLM-5.3"}, "reasoning": map[string]any{"defaultLevel": "max"}},
					map[string]any{"ref": map[string]any{"providerId": "account:zai-individual-coding-plan", "modelId": "GLM-5.3-Flash"}, "reasoning": map[string]any{"defaultLevel": "max"}},
				}}},
			})
		case "session/setModel":
			var params struct {
				SessionID string ` + "`json:\"sessionId\"`" + `
				Model struct {
					ProviderID string ` + "`json:\"providerId\"`" + `
					ModelID string ` + "`json:\"modelId\"`" + `
					Options struct { ReasoningLevel string ` + "`json:\"reasoningLevel\"`" + ` } ` + "`json:\"options\"`" + `
				} ` + "`json:\"model\"`" + `
			}
			if json.Unmarshal(message.Params, &params) != nil || params.SessionID != sessionID || params.Model.ProviderID != "account:zai-individual-coding-plan" || params.Model.ModelID == "" || params.Model.Options.ReasoningLevel != "max" {
				panic("non-canonical ZCode model selection")
			}
			modelSelected = true
			selection := map[string]any{"providerId": params.Model.ProviderID, "modelId": params.Model.ModelID, "options": map[string]any{"reasoningLevel": params.Model.Options.ReasoningLevel}}
			reply(message.ID, map[string]any{
				"protocol": map[string]any{"name": "ZCode Protocol", "version": 1},
				"session": map[string]any{"sessionId": sessionID, "model": selection},
				"settings": map[string]any{"model": map[string]any{"current": selection}},
			})
		case "session/send":
			var params struct {
				SessionID string ` + "`json:\"sessionId\"`" + `
				Content   string ` + "`json:\"content\"`" + `
			}
			if json.Unmarshal(message.Params, &params) != nil || params.Content == "" || !authAccepted || !modelSelected {
				panic("non-canonical ZCode session send")
			}
			prompt = params.Content
			capability = strings.Contains(prompt, "Prove readiness by returning exactly one JSON object and nothing else.")
			extraction := strings.Contains(prompt, "Mulgae admitted extraction target metadata")
			if capability {
				if mode != "plan" || denylist != "*" || allowlist == nil || len(allowlist) != 0 {
					panic("non-canonical ZCode capability conversation")
				}
			} else if extraction {
				if mode != "plan" || denylist != "*" || allowlist == nil || len(allowlist) != 0 {
					panic("non-canonical ZCode extraction conversation")
				}
			} else {
				if mode != "plan" || !strings.Contains(denylist, "Write") {
					panic("non-canonical ZCode review conversation")
				}
				switch {
				case strings.Contains(prompt, "\"scope\":\"workspace\""):
					if !slices.Equal(allowlist, []string{"Read", "Grep", "Glob", "Bash"}) {
						panic("non-canonical ZCode workspace review allowlist")
					}
				case strings.Contains(prompt, "\"scope\":\"stage\""),
					strings.Contains(prompt, "\"scope\":\"head\""),
					strings.Contains(prompt, "\"scope\":\"commit\""),
					strings.Contains(prompt, "\"scope\":\"diff\""):
					if !slices.Equal(allowlist, []string{"Read", "Bash"}) {
						panic("non-canonical ZCode git review allowlist")
					}
				default:
					panic("unrecognized ZCode review scope")
				}
			}
			destination := ""
			if strings.Contains(prompt, "Write your complete final Markdown role report to this exact absolute file path") { panic("live review granted report-file output") }
			cwd, cwdErr := os.Getwd()
			if cwdErr != nil {
				panic(cwdErr)
			}
			observe(observation{Argv: argv, CWD: cwd, Prompt: prompt, Destination: destination, ToolAllowlist: allowlist}, false)
			reply(message.ID, map[string]any{"accepted": true, "sessionId": sessionID, "stateRevision": 1})
			if capability {
				proof = capabilityProof(prompt)
				notifyTurn("turn-completed")
				continue
			}
			if destination != "" { panic("live review granted report-file output") }
			if !reviewFailureVariant() {
				waitForPeer()
				proof = report(prompt)
			}
			notifyTurn("turn-completed")
		case "session/messages":
			reply(message.ID, map[string]any{
				"messages": []any{map[string]any{
					"info":  map[string]any{"role": "assistant"},
					"parts": []any{map[string]any{"type": "text", "text": proof}},
				}},
			})
		case "session/close":
			reply(message.ID, map[string]any{"closed": true})
		default:
			panic("unexpected ZCode protocol method " + message.Method)
		}
	}
}

// capabilityProof extracts the controlled qualification binding from the
// packet and returns the JSON object a real provider would answer with.
func capabilityProof(prompt string) string {
	root := regexp.MustCompile("(?:root must be |root=)([0-9a-f]{64})").FindStringSubmatch(prompt)
	link := regexp.MustCompile("(?:link must be |link=)([^\\s;]+)").FindStringSubmatch(prompt)
	role := regexp.MustCompile("(?:role must be |role=)([a-z]+)").FindStringSubmatch(prompt)
	if len(root) != 2 || len(link) != 2 || len(role) != 2 {
		panic("native qualification reference did not resolve")
	}
	return fmt.Sprintf("{\"root\":%q,\"link\":%q,\"role\":%q}", root[1], link[1], role[1])
}

// reviewFailureVariant simulates a terminal provider failure or cancellation wait.
func reviewFailureVariant() bool {
	switch "__FAKE_ZCODE_MODE__" {
	case "wait_review":
		if barrierDirectory != "" { observe(observation{}, true) }
		for { time.Sleep(time.Second) }
	case "rate_limit_review":
		fmt.Fprintln(os.Stderr, "rate_limit")
		os.Exit(1)
	case "login_review":
		fmt.Fprintln(os.Stderr, "zcode login required")
		os.Exit(1)
	case "fail_review":
		fmt.Fprintln(os.Stderr, "provider execution failed")
		os.Exit(1)
	}
	return false
}

func observe(value observation, barrier bool) {
	connection, err := net.Dial("unix", "__FAKE_ZCODE_SOCKET__")
	if err != nil { panic(err) }
	defer connection.Close()
	if err := json.NewEncoder(connection).Encode(map[string]any{"observation": value, "barrier": barrier, "pid": os.Getpid()}); err != nil { panic(err) }
	var acknowledged bool
	if err := json.NewDecoder(connection).Decode(&acknowledged); err != nil || !acknowledged { panic("observer acknowledgement failed") }
}
func waitForPeer() {
	if barrierDirectory != "" { observe(observation{}, true) }
}

// report returns the complete assistant message for the requested role.
func report(prompt string) string {
	role := roleGuide.FindStringSubmatch(prompt)
	if len(role) != 2 {
		panic("ZCode review prompt omits the role guide")
	}
	if "__FAKE_ZCODE_MODE__" == "fail_security_review" && role[1] == "SECURITY" {
		deadline := time.Now().Add(30*time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(barrierDirectory+"/fail-security"); err == nil {
				fmt.Fprintln(os.Stderr, "provider execution failed")
				os.Exit(1)
			}
			time.Sleep(10*time.Millisecond)
		}
		panic("controlled security failure was not released")
	}
	return strings.ReplaceAll(__FAKE_ZCODE_REPORT_BODY__, "__ROLE__", strings.ToLower(role[1]))
}


`
	// Installed VM artifacts retain the real native user. Synthetic app-server
	// coordination cases never request that user\'s credentials; isolated-home
	// integration tests keep their existing authentication callback assertions.
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_RUNTIME_AUTH__", strconv.FormatBool(os.Getenv("MULGAE_VM_WORK_ROOT") == ""))
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_BARRIER__", strconv.Quote(barrier))
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_REPORT_BODY__", strconv.Quote(reportBody))
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_LOG__", logPath)
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_SOCKET__", fakeZCodeObserverSocket(logPath))
	program = strings.ReplaceAll(program, "__FAKE_ZCODE_MODE__", mode)
	mustWriteTestFile(t, source, []byte(program))
	build := exec.Command("go", "build", "-o", binary, source)
	build.Dir = root
	build.Env = goBuildEnv(os.Environ())
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake ZCode: %v\n%s", err, output)
	}
}
