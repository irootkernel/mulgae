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
	"slices"
	"strings"
	"testing"
	"time"
)

func TestIntegrationIsolatedReleaseFixtureLiveSelectors(t *testing.T) {
	source := repositoryRoot(t)
	binary := buildMulgaeBinary(t, source)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)
	runTestCommand(t, project, "git", "add", "review.go")
	runTestCommand(t, project, "git", "-c", "user.name=Mulgae E2E", "-c", "user.email=mulgae-e2e@example.invalid", "commit", "-m", "index baseline")
	mustWriteTestFile(t, filepath.Join(project, "review.go"), []byte("package review\n\nconst state = \"index\"\n"))
	runTestCommand(t, project, "git", "add", "review.go")
	mustWriteTestFile(t, filepath.Join(project, "review.go"), []byte("package review\n\nconst state = \"workspace\"\n"))
	providers := canonicalTestTempDir(t)
	log := filepath.Join(canonicalTestTempDir(t), "provider.jsonl")
	mustWriteTestFile(t, log, nil)
	bundle, node, launcher := fakeZCodeAppPaths(providers)
	buildFakeZCode(t, source, node, launcher, log, "success")
	native := integrationNativeHome(t, binary)
	environment := isolatedMulgaeEnvWith(t, native, providers)
	initializeOfflineProvidersForRoles(t, binary, project, environment, "zcode", "logic", bundle)
	for _, selector := range [][]string{{"--workspace"}, {"--stage"}, {"--head"}, {"--commit", "HEAD"}, {"--diff", "HEAD~1..HEAD"}, {"--diff", "HEAD~1...HEAD"}} {
		t.Run(selector[0]+selector[len(selector)-1], func(t *testing.T) {
			beforeReviews := len(fakeZCodeReviewObservations(t, log))
			arguments := append(append([]string{"review"}, selector...), "--roles", "logic", "--output", "json")
			plan := runMulgaeBinaryWithEnv(t, binary, project, environment, append(arguments, "--preflight")...)
			if plan.exitCode != 0 {
				t.Fatalf("preflight %v: %s %s", selector, plan.stdout, plan.stderr)
			}
			result := runMulgaeBinaryWithEnv(t, binary, project, environment, arguments...)
			var envelope commandEnvelope
			if err := json.Unmarshal(result.stdout, &envelope); err != nil {
				t.Fatal(err)
			}
			if result.exitCode != 0 || envelope.Result.RunID == nil {
				logFakeProviderPanic(t, project)
				dumpRuntimeDiagnostics(t, project, envelope)
				t.Fatalf("selector %v: %s %s", selector, result.stdout, result.stderr)
			}
			afterReviews := fakeZCodeReviewObservations(t, log)
			if len(afterReviews) != beforeReviews+1 {
				t.Fatalf("selector %v review launches = %d, want %d", selector, len(afterReviews)-beforeReviews, 1)
			}
			wantAllowlist := []string{"Read", "Bash", "Write"}
			if selector[0] == "--workspace" {
				wantAllowlist = []string{"Read", "Grep", "Glob", "Write"}
			}
			if got := afterReviews[len(afterReviews)-1].ToolAllowlist; !slices.Equal(got, wantAllowlist) {
				t.Fatalf("selector %v toolAllowlist = %v, want %v", selector, got, wantAllowlist)
			}
			inspected := runMulgaeBinaryWithEnv(t, binary, project, environment, "inspect", "--run", *envelope.Result.RunID, "--output", "json")
			var inspection struct {
				Result struct {
					CaptureAvailability string `json:"capture_availability"`
					SourceIdentity      string `json:"source_identity_sha256"`
					CaptureIdentity     string `json:"capture_identity"`
				}
			}
			if err := json.Unmarshal(inspected.stdout, &inspection); err != nil {
				t.Fatal(err)
			}
			if inspected.exitCode != 0 || inspection.Result.CaptureAvailability != "not_captured" || !consumerDigest(inspection.Result.SourceIdentity) || inspection.Result.CaptureIdentity != "" {
				t.Fatalf("live scope lost explicit source identity: %s", inspected.stdout)
			}
			runRoot := filepath.Join(project, ".mulgae", *envelope.Result.SessionID, *envelope.Result.RunID)
			for _, retired := range []string{"target/capture-manifest.json", "target/captured-archive.json", "target/target.txt", "workspace"} {
				if _, err := os.Lstat(filepath.Join(runRoot, retired)); !os.IsNotExist(err) {
					t.Fatalf("new run retained retired source snapshot %s: %v", retired, err)
				}
			}
		})
	}
	t.Run("non-Git workspace", func(t *testing.T) {
		nonGit := canonicalTestTempDir(t)
		mustWriteTestFile(t, filepath.Join(nonGit, "review.go"), []byte("package review\n"))
		initializeOfflineProvidersForRoles(t, binary, nonGit, environment, "zcode", "logic", bundle)
		before := len(fakeZCodeReviewObservations(t, log))
		preflight := runMulgaeBinaryWithEnv(t, binary, nonGit, environment, "review", "--workspace", "--preflight", "--output", "json")
		var plan struct {
			Result struct {
				Preflight struct {
					ProjectBinding string `json:"project_binding"`
					Capabilities   struct {
						ProjectBinding string `json:"project_binding"`
					} `json:"capabilities"`
				} `json:"preflight"`
			} `json:"result"`
		}
		if err := json.Unmarshal(preflight.stdout, &plan); err != nil {
			t.Fatal(err)
		}
		if preflight.exitCode != 0 || plan.Result.Preflight.ProjectBinding != "" || plan.Result.Preflight.Capabilities.ProjectBinding != "" || len(fakeZCodeReviewObservations(t, log)) != before {
			t.Fatalf("non-Git preflight fabricated binding or called a provider: %s %s", preflight.stdout, preflight.stderr)
		}
		for _, selector := range [][]string{{"--workspace", "--expected-project-binding", "sha256:" + strings.Repeat("a", 64)}, {"--head"}} {
			args := append([]string{"review"}, selector...)
			args = append(args, "--preflight", "--output", "json")
			rejected := runMulgaeBinaryWithEnv(t, binary, nonGit, environment, args...)
			if rejected.exitCode == 0 || len(fakeZCodeReviewObservations(t, log)) != before {
				t.Fatalf("non-Git admitted unavailable authority: %s", rejected.stdout)
			}
		}
		result := runMulgaeBinaryWithEnv(t, binary, nonGit, environment, "review", "--workspace", "--output", "json")
		var envelope commandEnvelope
		if err := json.Unmarshal(result.stdout, &envelope); err != nil {
			t.Fatal(err)
		}
		if result.exitCode != 0 || envelope.Result.RunID == nil || len(fakeZCodeReviewObservations(t, log)) != before+1 {
			t.Fatalf("non-Git workspace execution failed: %s %s", result.stdout, result.stderr)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		server := exec.CommandContext(ctx, binary, "mcp", "--project-root", nonGit)
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
				t.Errorf("non-Git MCP: %v: %s", err, stderr.String())
			}
		}()
		reader := bufio.NewReader(stdout)
		requestID := 0
		rpc := func(method string, params any) json.RawMessage {
			t.Helper()
			requestID++
			raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": requestID, "method": method, "params": params})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintln(stdin, string(raw)); err != nil {
				t.Fatal(err)
			}
			line, err := reader.ReadBytes('\n')
			if err != nil {
				t.Fatalf("non-Git MCP response: %v: %s", err, stderr.String())
			}
			var response struct {
				ID     int             `json:"id"`
				Result json.RawMessage `json:"result"`
				Error  json.RawMessage `json:"error"`
			}
			if err := json.Unmarshal(line, &response); err != nil {
				t.Fatal(err)
			}
			if response.ID != requestID || len(response.Error) != 0 {
				t.Fatalf("non-Git MCP protocol: %s", line)
			}
			return response.Result
		}
		rpc("initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "non-git-consumer", "version": "1"}})
		if _, err := fmt.Fprintln(stdin, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); err != nil {
			t.Fatal(err)
		}
		tool := func(name string, arguments map[string]any, rejected bool) verifiedConsumerResult {
			t.Helper()
			var call struct {
				Structured json.RawMessage `json:"structuredContent"`
			}
			if err := json.Unmarshal(rpc("tools/call", map[string]any{"name": name, "arguments": arguments}), &call); err != nil {
				t.Fatal(err)
			}
			var envelope struct {
				Outcome string `json:"outcome"`
			}
			if err := json.Unmarshal(call.Structured, &envelope); err != nil {
				t.Fatal(err)
			}
			if rejected {
				if envelope.Outcome != "error" {
					t.Fatalf("non-Git MCP admitted unavailable authority: %s", call.Structured)
				}
				return verifiedConsumerResult{}
			}
			data, err := decodeVerifiedConsumerEnvelope(call.Structured, "mcp", name, false)
			if err != nil {
				t.Fatal(err)
			}
			var value verifiedConsumerResult
			if err := json.Unmarshal(data, &value); err != nil {
				t.Fatal(err)
			}
			return value
		}
		arguments := map[string]any{"target": map[string]any{"kind": "workspace"}, "roles": []string{"logic"}}
		mcpPlan := tool("preflight_review", arguments, false)
		if mcpPlan.ProjectBinding != "" || mcpPlan.Capabilities["project_binding"] != "" || !consumerDigest(mcpPlan.SourceIdentity) {
			t.Fatal("non-Git MCP preflight lost honest binding/source metadata")
		}
		guarded := map[string]any{"target": map[string]any{"kind": "workspace"}, "expected_project_binding": "sha256:" + strings.Repeat("a", 64)}
		tool("preflight_review", guarded, true)
		rejectedStart := tool("start_review", guarded, false)
		if rejectedStart.InvocationID == "" {
			t.Fatal("rejected execution lost invocation correlation")
		}
		tool("await_review", map[string]any{"invocation_id": rejectedStart.InvocationID}, true)
		if len(fakeZCodeReviewObservations(t, log)) != before+1 {
			t.Fatal("non-Git guard rejection invoked a provider")
		}
		started := tool("start_review", arguments, false)
		if started.InvocationID == "" {
			t.Fatal("non-Git MCP start omitted invocation identity")
		}
		completed := tool("await_review", map[string]any{"invocation_id": started.InvocationID}, false)
		if completed.RunID == "" || completed.TerminalExitCode != 0 || completed.Guarded || completed.ProjectBinding != "" || completed.SourceIdentity != mcpPlan.SourceIdentity || len(fakeZCodeReviewObservations(t, log)) != before+2 {
			t.Fatalf("non-Git MCP completion lost authority: %+v", completed)
		}
	})
	t.Run("two-role shared ZCode qualification", func(t *testing.T) {
		sharedProject := canonicalTestTempDir(t)
		initializeReviewGitRepository(t, sharedProject)
		runTestCommand(t, sharedProject, "git", "add", "review.go")
		initializeOfflineProvidersForRoles(t, binary, sharedProject, environment, "zcode", "logic,security", bundle)
		countCapabilities := func() int {
			count := 0
			for _, obs := range readFakeZCodeObservations(t, log) {
				if strings.Contains(obs.Prompt, "Prove readiness by returning exactly one JSON object and nothing else.") {
					count++
				}
			}
			return count
		}
		beforeCapabilities := countCapabilities()
		beforeReviews := len(fakeZCodeReviewObservations(t, log))
		result := runMulgaeBinaryWithEnv(t, binary, sharedProject, environment, "review", "--stage", "--roles", "logic,security", "--output", "json")
		var envelope commandEnvelope
		if err := json.Unmarshal(result.stdout, &envelope); err != nil {
			t.Fatal(err)
		}
		if result.exitCode != 0 || envelope.Result.RunID == nil {
			logFakeProviderPanic(t, sharedProject)
			t.Fatalf("two-role shared ZCode review failed: %s %s", result.stdout, result.stderr)
		}
		if got := countCapabilities() - beforeCapabilities; got != 1 {
			t.Fatalf("two-role ZCode capability probes = %d, want 1 shared probe", got)
		}
		afterReviews := fakeZCodeReviewObservations(t, log)
		if len(afterReviews) != beforeReviews+2 {
			t.Fatalf("two-role ZCode review launches = %d, want 2", len(afterReviews)-beforeReviews)
		}
		for _, launch := range afterReviews[beforeReviews:] {
			if !slices.Equal(launch.ToolAllowlist, []string{"Read", "Bash", "Write"}) {
				t.Fatalf("two-role stage toolAllowlist = %v, want [Read Bash Write]", launch.ToolAllowlist)
			}
		}
	})
	t.Run("ZCode heartbeat without a logic role route", func(t *testing.T) {
		heartbeatProject := canonicalTestTempDir(t)
		mustWriteTestFile(t, filepath.Join(heartbeatProject, "readme.md"), []byte("heartbeat fixture\n"))
		initializeOfflineProvidersForRoles(t, binary, heartbeatProject, environment, "zcode", "security", bundle)
		before := len(readFakeZCodeObservations(t, log))
		observed := runMulgaeBinaryWithEnv(t, binary, heartbeatProject, environment,
			"heartbeat", "--provider", "zcode", "--authorize-live-request", "--output", "json")
		var envelope struct {
			Result struct {
				Heartbeat struct {
					Attempted bool   `json:"attempted"`
					Status    string `json:"status"`
				} `json:"heartbeat"`
			} `json:"result"`
		}
		if err := json.Unmarshal(observed.stdout, &envelope); err != nil {
			t.Fatal(err)
		}
		if observed.exitCode != 0 || !envelope.Result.Heartbeat.Attempted || envelope.Result.Heartbeat.Status != "succeeded" {
			t.Fatalf("ZCode heartbeat failed: %s %s", observed.stdout, observed.stderr)
		}
		after := readFakeZCodeObservations(t, log)
		if len(after) != before+1 || filepath.Base(after[before].Destination) != "probe.json" || !slices.Equal(after[before].ToolAllowlist, []string{"Read", "Write"}) {
			t.Fatal("heartbeat did not use one shell-free terminal qualification")
		}
		if _, err := os.Lstat(after[before].Destination); !os.IsNotExist(err) {
			t.Fatalf("heartbeat staged output survived cleanup: %v", err)
		}
	})

	for _, launch := range fakeZCodeReviewObservations(t, log) {
		if launch.CWD != filepath.Join(native, ".mulgae", "home") || filepath.Base(launch.Destination) != "role-report.md" {
			t.Fatalf("review used unexpected cwd or destination: %q, %q", launch.CWD, launch.Destination)
		}
		if _, err := os.Lstat(launch.Destination); !os.IsNotExist(err) {
			t.Fatalf("staged review output survived cleanup: %v", err)
		}
	}
}
