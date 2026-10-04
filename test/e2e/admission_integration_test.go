//go:build darwin && arm64

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIntegrationIsolatedReleaseFixtureGuardedAdmission(t *testing.T) {
	source := repositoryRoot(t)
	binary := buildMulgaeBinary(t, source)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)
	nativeHome := integrationNativeHome(t, binary)
	providerDirectory := canonicalTestTempDir(t)
	providerLog := filepath.Join(canonicalTestTempDir(t), "provider.jsonl")
	appBundle, node, launcher := fakeZCodeAppPaths(providerDirectory)
	buildFakeZCode(t, source, node, launcher, providerLog, "success")
	environment := isolatedMulgaeEnvWith(t, nativeHome, providerDirectory)
	initializeOfflineProvidersForRoles(t, binary, project, environment, "zcode", "logic", appBundle)
	run := func(want int, args ...string) map[string]any {
		t.Helper()
		result := runMulgaeBinaryWithEnv(t, binary, project, environment, args...)
		if result.exitCode != want {
			logFakeProviderPanic(t, project)
			t.Fatalf("%v: exit=%d stdout=%s stderr=%s", args, result.exitCode, result.stdout, result.stderr)
		}
		var envelope map[string]any
		if err := json.Unmarshal(result.stdout, &envelope); err != nil {
			t.Fatalf("decode %v: %v %s", args, err, result.stdout)
		}
		return envelope
	}
	preflight := func(mode string) map[string]any {
		t.Helper()
		return run(0, "review", mode, "--roles", "logic", "--preflight", "--output", "json")["result"].(map[string]any)["preflight"].(map[string]any)
	}
	binding := run(0, "context", "--output", "json")["result"].(map[string]any)["project_binding"].(string)
	guards := func(map[string]any) []string { return []string{"--expected-project-binding", binding} }
	stage := preflight("--stage")
	if stage["status"] != "no_change" {
		t.Fatal("stage fixture changed")
	}
	baselineLog, _ := os.ReadFile(providerLog)
	execute := func(mode string, p map[string]any, extra ...string) map[string]any {
		args := append([]string{"review", mode, "--roles", "logic", "--output", "json"}, guards(p)...)
		args = append(args, extra...)
		return run(0, args...)["result"].(map[string]any)
	}
	first := execute("--stage", stage)
	second := execute("--stage", stage)
	if first["guarded"] != true || first["source_identity_sha256"] != stage["source_identity_sha256"] || first["run_id"] == second["run_id"] {
		t.Fatal("guard result or repeated-start identity invalid")
	}
	afterLog, _ := os.ReadFile(providerLog)
	if string(afterLog) != string(baselineLog) {
		t.Fatal("no-change invoked provider")
	}
	// A different process verifies the newly retained support after publication.
	run(0, "status", "--run", first["run_id"].(string), "--output", "json")
	args := []string{"review", "--stage", "--roles", "logic", "--expected-project-binding", "sha256:" + strings.Repeat("a", 64), "--output", "json"}
	rejected := run(2, args...)
	reasons, _ := json.Marshal(rejected["reasons"])
	if !strings.Contains(string(reasons), "project_binding_mismatch") {
		t.Fatalf("wrong admission rejection: %s", reasons)
	}
	afterLog, _ = os.ReadFile(providerLog)
	if string(afterLog) != string(baselineLog) {
		t.Fatal("mismatch invoked provider")
	}
	checkGuardedMCPReview(t, binary, project, environment, stage)
	afterLog, _ = os.ReadFile(providerLog)
	if string(afterLog) != string(baselineLog) {
		t.Fatal("MCP no-change or rejection invoked provider")
	}
	for _, retired := range [][]string{
		{"review", "--dirty"}, {"review", "--stdin"}, {"review", "--patch", "target.diff"},
		{"review", "--workspace", "--expected-request-digest", "sha256:" + strings.Repeat("b", 64)},
		{"followup"}, {"delta"}, {"rerun"}, {"compose"},
	} {
		result := runMulgaeBinaryWithEnv(t, binary, project, environment, append(retired, "--output", "json")...)
		if result.exitCode != 2 || len(result.stdout) != 0 || len(result.stderr) == 0 {
			t.Fatalf("retired grammar admitted: %v: %+v", retired, result)
		}
	}
	if after, _ := os.ReadFile(providerLog); !bytes.Equal(after, baselineLog) {
		t.Fatal("retired request invoked provider")
	}
	accepted := execute("--workspace", preflight("--workspace"))
	if accepted["guarded"] != true {
		t.Fatal("live review not guarded")
	}
	run(0, "status", "--run", accepted["run_id"].(string), "--output", "json")
	manifest := filepath.Join(project, ".mulgae", first["session_id"].(string), first["run_id"].(string), "source", "source.json")
	mustWriteTestFile(t, manifest, []byte("corrupt fixture source metadata"))
	run(7, "status", "--run", first["run_id"].(string), "--output", "json")

}

func checkGuardedMCPReview(t *testing.T, binary, project string, environment []string, cliPreflight map[string]any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	server := exec.CommandContext(ctx, binary, "mcp", "--project-root", project)
	server.Dir, server.Env = t.TempDir(), environment
	stdin, err := server.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := server.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	server.Stderr = &stderr
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = stdin.Close()
		if err := server.Wait(); err != nil {
			t.Errorf("MCP exit: %v; %s", err, stderr.String())
		}
	}()
	reader := bufio.NewReader(stdout)
	id := 0
	call := func(method string, params any) map[string]any {
		t.Helper()
		id++
		request, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintln(stdin, string(request)); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadBytes('\n')
		if err != nil {
			t.Fatalf("MCP response: %v", err)
		}
		var response map[string]any
		if err := json.Unmarshal(line, &response); err != nil {
			t.Fatal(err)
		}
		if response["error"] != nil {
			t.Fatalf("MCP protocol error: %s", line)
		}
		return response["result"].(map[string]any)
	}
	call("initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "admission-fixture", "version": "1"}})
	if _, err := fmt.Fprintln(stdin, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); err != nil {
		t.Fatal(err)
	}
	tool := func(name string, arguments map[string]any) map[string]any {
		t.Helper()
		return call("tools/call", map[string]any{"name": name, "arguments": arguments})["structuredContent"].(map[string]any)
	}
	binding := cliPreflight["project_binding"].(string)
	arguments := map[string]any{"target": map[string]any{"kind": "stage"}, "roles": []string{"logic"}, "expected_project_binding": binding}
	preflight := tool("preflight_review", arguments)
	if preflight["outcome"] != "success" || preflight["data"].(map[string]any)["source_identity_sha256"] != cliPreflight["source_identity_sha256"] {
		t.Fatalf("CLI/MCP receipt mismatch: %#v", preflight)
	}
	foreground := tool("run_review", arguments)
	if foreground["outcome"] != "success" || foreground["data"].(map[string]any)["guarded"] != true {
		t.Fatalf("guarded foreground: %#v", foreground)
	}
	started := tool("start_review", arguments)
	if started["outcome"] != "success" {
		t.Fatalf("guarded start: %#v", started)
	}
	invocation := started["data"].(map[string]any)["invocation_id"].(string)
	terminal := tool("await_review", map[string]any{"invocation_id": invocation})
	if terminal["outcome"] != "success" || terminal["data"].(map[string]any)["source_identity_sha256"] != cliPreflight["source_identity_sha256"] || terminal["data"].(map[string]any)["run_id"] == foreground["data"].(map[string]any)["run_id"] {
		t.Fatalf("guarded await: %#v", terminal)
	}
	arguments["expected_project_binding"] = "sha256:" + strings.Repeat("a", 64)
	rejected := tool("run_review", arguments)
	if rejected["outcome"] != "error" || rejected["error"].(map[string]any)["code"] != "project_binding_mismatch" {
		t.Fatalf("foreign project admitted: %#v", rejected)
	}
}
