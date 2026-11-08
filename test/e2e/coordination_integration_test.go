//go:build darwin && arm64

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/testsupport/haeparifixture"
)

type coordinationMCP struct {
	input  io.WriteCloser
	output *bufio.Reader
	id     int
}

func startCoordinationMCP(t *testing.T, ctx context.Context, binary, project string, environment []string) *coordinationMCP {
	t.Helper()
	command := exec.CommandContext(ctx, binary, "mcp", "--project-root", project)
	command.Dir, command.Env = t.TempDir(), environment
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = input.Close()
		if err := command.Wait(); err != nil {
			t.Errorf("MCP process: %v / %s", err, stderr.String())
		}
	})
	client := &coordinationMCP{input: input, output: bufio.NewReader(output)}
	if _, err := client.rpc("initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "coordination-fixture", "version": "1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(input, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); err != nil {
		t.Fatal(err)
	}
	return client
}

func (client *coordinationMCP) rpc(method string, params any) (json.RawMessage, error) {
	client.id++
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": client.id, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintln(client.input, string(raw)); err != nil {
		return nil, err
	}
	line, err := client.output.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var response struct {
		ID     int             `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return nil, err
	}
	if response.ID != client.id || len(response.Error) != 0 {
		return nil, fmt.Errorf("unexpected MCP response: %s", line)
	}
	return response.Result, nil
}

func (client *coordinationMCP) tool(name string, arguments any) (map[string]any, error) {
	raw, err := client.rpc("tools/call", map[string]any{"name": name, "arguments": arguments})
	if err != nil {
		return nil, err
	}
	var result struct {
		Structured map[string]any `json:"structuredContent"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return result.Structured, nil
}

func TestIntegrationSharedHaepariInstallationSerializesCLIAndMCP(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	providers := canonicalTestTempDir(t)
	bundle, node, launcher := fakeZCodeAppPaths(providers)
	buildFakeZCode(t, root, node, launcher, filepath.Join(canonicalTestTempDir(t), "provider.jsonl"), "success")
	native := integrationNativeHome(t, binary)
	for _, route := range []string{"cli", "foreground", "async", "cancel"} {
		t.Run(route, func(t *testing.T) {
			controller := haeparifixture.New(t)
			unblock := controller.PauseNextRelease()
			defer unblock()
			environment := withHaepariHome(isolatedMulgaeEnvWith(t, native, providers), controller.Home)
			firstProject, secondProject := canonicalTestTempDir(t), canonicalTestTempDir(t)
			for _, project := range []string{firstProject, secondProject} {
				initializeReviewGitRepository(t, project)
				runTestCommand(t, project, "git", "add", "review.go")
				runTestCommand(t, project, "git", "-c", "user.name=Mulgae E2E", "-c", "user.email=mulgae-e2e@example.invalid", "commit", "-m", "review target")
				initializeOfflineProvidersForRoles(t, binary, project, environment, "zcode", "logic,security", bundle)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			t.Cleanup(cancel)
			first := startMulgaeBinaryWithEnv(t, ctx, binary, firstProject, environment, "review", "--head", "--roles", "logic,security", "--output", "json")
			if err := controller.WaitFor(ctx, "release_pending:"); err != nil {
				t.Fatal(err)
			}
			var second *runningBinary
			var client *coordinationMCP
			var invocation string
			completed := make(chan struct {
				result map[string]any
				err    error
			}, 1)
			arguments := map[string]any{"target": map[string]any{"kind": "head"}, "roles": []string{"logic"}}
			if route == "cli" {
				second = startMulgaeBinaryWithEnv(t, ctx, binary, secondProject, environment, "review", "--head", "--roles", "logic", "--output", "json")
			} else {
				client = startCoordinationMCP(t, ctx, binary, secondProject, environment)
				if route == "foreground" {
					go func() {
						result, err := client.tool("run_review", arguments)
						completed <- struct {
							result map[string]any
							err    error
						}{result, err}
					}()
				} else {
					started, err := client.tool("start_review", arguments)
					if err != nil {
						t.Fatal(err)
					}
					data, ok := started["data"].(map[string]any)
					if !ok {
						t.Fatalf("start envelope: %+v", started)
					}
					invocation, _ = data["invocation_id"].(string)
					if invocation == "" {
						t.Fatalf("missing invocation: %+v", started)
					}
				}
			}
			if err := controller.WaitFor(ctx, "queued:request-2"); err != nil {
				t.Fatal(err)
			}
			if err := controller.WaitFor(ctx, "wait:request-2"); err != nil {
				t.Fatal(err)
			}
			for _, event := range controller.Events() {
				if event == "granted:request-2" {
					t.Fatal("second review bypassed shared grant")
				}
			}
			if route == "cancel" {
				if _, err := client.tool("cancel_review", map[string]any{"invocation_id": invocation}); err != nil {
					t.Fatal(err)
				}
				if err := controller.WaitFor(ctx, "cancel:request-2"); err != nil {
					t.Fatal(err)
				}
				result, err := client.tool("await_review", map[string]any{"invocation_id": invocation})
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(result)
				if result["outcome"] != "error" || !bytes.Contains(raw, []byte("haepari_cancelled")) {
					t.Fatalf("queued cancellation lost typed reason: %s", raw)
				}
			}
			unblock()
			assertSuccessfulConcurrentReview(t, firstProject, waitMulgaeBinary(t, first))
			switch route {
			case "cli":
				assertSuccessfulConcurrentReview(t, secondProject, waitMulgaeBinary(t, second))
			case "foreground":
				result := <-completed
				if result.err != nil || result.result["outcome"] != "success" {
					t.Fatalf("foreground completion: %+v / %v", result.result, result.err)
				}
			case "async":
				result, err := client.tool("await_review", map[string]any{"invocation_id": invocation})
				if err != nil || result["outcome"] != "success" {
					t.Fatalf("async completion: %+v / %v", result, err)
				}
			}
			events := controller.Events()
			released, granted := -1, -1
			for index, event := range events {
				if strings.HasPrefix(event, "release:grant-1") {
					released = index
				}
				if event == "granted:request-2" {
					granted = index
				}
			}
			if route == "cancel" {
				if granted != -1 {
					t.Fatalf("cancelled request later granted: %v", events)
				}
			} else if released < 0 || granted <= released {
				t.Fatalf("grant preceded verified first disposition: %v", events)
			}
		})
	}
}

func TestIntegrationCoordinationProviderFreeAndInheritedGrant(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)
	runTestCommand(t, project, "git", "add", "review.go")
	runTestCommand(t, project, "git", "-c", "user.name=Mulgae E2E", "-c", "user.email=mulgae-e2e@example.invalid", "commit", "-m", "review target")
	providers := canonicalTestTempDir(t)
	bundle, node, launcher := fakeZCodeAppPaths(providers)
	log := filepath.Join(canonicalTestTempDir(t), "provider.jsonl")
	mustWriteTestFile(t, log, nil)
	buildFakeZCode(t, root, node, launcher, log, "success")
	environment := isolatedMulgaeEnvWith(t, integrationNativeHome(t, binary), providers)
	initializeOfflineProvidersForRoles(t, binary, project, environment, "zcode", "logic", bundle)
	controllerFree := append(withHaepariHome(environment, "/missing-coordination-fixture"), "HAEPARI_LOCK_GRANT=")
	for _, arguments := range [][]string{
		{"review", "--stage", "--roles", "logic", "--output", "json"},
		{"review", "--head", "--roles", "logic", "--preflight", "--output", "json"},
	} {
		result := runMulgaeBinaryWithEnv(t, binary, project, controllerFree, arguments...)
		if result.exitCode != 0 {
			t.Fatalf("provider-free request contacted inherited coordination: %s / %s", result.stdout, result.stderr)
		}
	}
	for _, value := range []string{"", " ", `{"installation_id":"fixture-installation","lock_id":"mulgae-review","grant_id":"grant-1","generation":1}`} {
		env := append(withHaepariHome(environment, "/missing-coordination-fixture"), "HAEPARI_LOCK_GRANT="+value)
		result := runMulgaeBinaryWithEnv(t, binary, project, env, "review", "--head", "--roles", "logic", "--output", "json")
		if result.exitCode != 2 || !bytes.Contains(result.stdout, []byte("haepari_readiness_failed")) || bytes.Contains(result.stdout, []byte("missing-coordination-fixture")) {
			t.Fatalf("inherited grant did not fail closed with bounded projection: %d / %s / %s", result.exitCode, result.stdout, result.stderr)
		}
	}
	if observations := fakeZCodeReviewObservations(t, log); len(observations) != 0 {
		t.Fatalf("provider-free or refused requests invoked provider: %+v", observations)
	}

	// Active parent grant on isolated controller: borrowed child CLI, foreground MCP,
	// and async MCP reviews succeed read-only without mutating the parent grant, and
	// child artifacts can be cleaned while the parent remains live.
	controller := haeparifixture.New(t)
	unblockParent := controller.PauseNextRelease()
	defer unblockParent()
	parentEnv := withHaepariHome(environment, controller.Home)
	parentProject := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, parentProject)
	runTestCommand(t, parentProject, "git", "add", "review.go")
	runTestCommand(t, parentProject, "git", "-c", "user.name=Mulgae E2E", "-c", "user.email=mulgae-e2e@example.invalid", "commit", "-m", "review target")
	initializeOfflineProvidersForRoles(t, binary, parentProject, parentEnv, "zcode", "logic", bundle)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	parentProc := startMulgaeBinaryWithEnv(t, ctx, binary, parentProject, parentEnv, "review", "--head", "--roles", "logic", "--output", "json")
	if err := controller.WaitFor(ctx, "release_pending:grant-1"); err != nil {
		t.Fatal(err)
	}
	rawGrant := controller.ActiveGrantJSON()
	if rawGrant == "" {
		t.Fatal("expected active parent grant JSON from controller")
	}
	borrowedEnv := append(withHaepariHome(environment, controller.Home), "HAEPARI_LOCK_GRANT="+rawGrant)

	// 1. Borrowed CLI child review + independent child clean while parent is still holding grant-1.
	cliChildRes := runMulgaeBinaryWithEnv(t, binary, project, borrowedEnv, "review", "--head", "--roles", "logic", "--output", "json")
	assertSuccessfulConcurrentReview(t, project, cliChildRes)
	cleanRes := runMulgaeBinaryWithEnv(t, binary, project, borrowedEnv, "clean", "--all", "--output", "json")
	if cleanRes.exitCode != 0 {
		t.Fatalf("expected borrowed child clean to succeed while parent grant remains live: %d / %s / %s", cleanRes.exitCode, cleanRes.stdout, cleanRes.stderr)
	}

	// 2. Borrowed foreground and async MCP child reviews under the same active parent grant.
	mcpClient := startCoordinationMCP(t, ctx, binary, project, borrowedEnv)
	arguments := map[string]any{"target": map[string]any{"kind": "head"}, "roles": []string{"logic"}}
	fgResult, err := mcpClient.tool("run_review", arguments)
	if err != nil || fgResult["outcome"] != "success" {
		t.Fatalf("borrowed foreground MCP review failed: %+v / %v", fgResult, err)
	}
	started, err := mcpClient.tool("start_review", arguments)
	if err != nil {
		t.Fatal(err)
	}
	data, ok := started["data"].(map[string]any)
	if !ok {
		t.Fatalf("borrowed start_review envelope: %+v", started)
	}
	invocation, _ := data["invocation_id"].(string)
	if invocation == "" {
		t.Fatalf("missing invocation_id: %+v", started)
	}
	asyncResult, err := mcpClient.tool("await_review", map[string]any{"invocation_id": invocation})
	if err != nil || asyncResult["outcome"] != "success" {
		t.Fatalf("borrowed async MCP review failed: %+v / %v", asyncResult, err)
	}

	// Verify zero child lock mutations occurred while parent held grant-1.
	listEvents := 0
	for _, event := range controller.Events() {
		if event == "list" {
			listEvents++
		}
		if event == "queued:request-2" || event == "granted:request-2" || strings.HasPrefix(event, "cancel:") {
			t.Fatalf("borrowed child review mutated controller lock state: %v", controller.Events())
		}
	}
	if listEvents < 3 {
		t.Fatalf("expected read-only locks.list calls from borrowed CLI/MCP children, got %d (%v)", listEvents, controller.Events())
	}

	unblockParent()
	assertSuccessfulConcurrentReview(t, parentProject, waitMulgaeBinary(t, parentProc))
}
