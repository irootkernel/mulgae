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
	guards := func(p map[string]any) []string {
		return []string{"--expected-project-binding", p["project_binding"].(string), "--expected-request-digest", p["request_receipt"].(map[string]any)["request_digest"].(string)}
	}
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
	if first["guarded"] != true || first["request_digest"] != stage["request_receipt"].(map[string]any)["request_digest"] || first["run_id"] == second["run_id"] {
		t.Fatal("guard result or repeated-start identity invalid")
	}
	afterLog, _ := os.ReadFile(providerLog)
	if string(afterLog) != string(baselineLog) {
		t.Fatal("no-change invoked provider")
	}
	// A different process verifies the newly retained support after publication.
	run(0, "status", "--run", first["run_id"].(string), "--output", "json")
	args := append([]string{"review", "--stage", "--roles", "logic", "--objective", "changed objective", "--output", "json"}, guards(stage)...)
	rejected := run(2, args...)
	reasons, _ := json.Marshal(rejected["reasons"])
	if !strings.Contains(string(reasons), "request_digest_mismatch") {
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
	dirty := preflight("--dirty")
	mustWriteTestFile(t, filepath.Join(project, "docs", "linked.md"), []byte("changed unchanged-side support\n"))
	args = append([]string{"review", "--dirty", "--roles", "logic", "--output", "json"}, guards(dirty)...)
	run(2, args...)
	accepted := execute("--dirty", preflight("--dirty"))
	if accepted["guarded"] != true {
		t.Fatal("changed review not guarded")
	}
	run(0, "status", "--run", accepted["run_id"].(string), "--output", "json")
	// Corruption is tested only inside this disposable fixture publication.
	manifest := filepath.Join(project, ".mulgae", first["session_id"].(string), first["run_id"].(string), "target", "capture-manifest.json")
	mustWriteTestFile(t, manifest, []byte("corrupt fixture capture"))
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
	digest := cliPreflight["request_receipt"].(map[string]any)["request_digest"].(string)
	arguments := map[string]any{"target": map[string]any{"kind": "stage"}, "roles": []string{"logic"}, "expected_project_binding": binding}
	preflight := tool("preflight_review", arguments)
	if preflight["outcome"] != "success" || preflight["data"].(map[string]any)["request_receipt"].(map[string]any)["request_digest"] != digest {
		t.Fatalf("CLI/MCP receipt mismatch: %#v", preflight)
	}
	arguments["expected_request_digest"] = digest
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
	if terminal["outcome"] != "success" || terminal["data"].(map[string]any)["request_digest"] != digest || terminal["data"].(map[string]any)["run_id"] == foreground["data"].(map[string]any)["run_id"] {
		t.Fatalf("guarded await: %#v", terminal)
	}
	arguments["expected_project_binding"] = "sha256:" + strings.Repeat("a", 64)
	rejected := tool("run_review", arguments)
	if rejected["outcome"] != "error" || rejected["error"].(map[string]any)["code"] != "project_binding_mismatch" {
		t.Fatalf("foreign project admitted: %#v", rejected)
	}
}
