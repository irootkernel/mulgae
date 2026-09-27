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
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestIntegrationIsolatedReleaseFixtureProjectContext(t *testing.T) {
	source, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binary := buildMulgaeBinary(t, source)
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "ProjectRoot")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	initializeReviewGitRepository(t, project)
	// A configuration read would block. Context must inspect only directory and
	// gitdir/commondir metadata, even when configuration is unreadable.
	config := filepath.Join(project, ".git", "config")
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(config, 0600); err != nil {
		t.Fatal(err)
	}
	before := contextFixtureFiles(t, project)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	environment := isolatedMulgaeEnv(t)
	// No provider or Git executable is reachable during either lookup.
	for i, value := range environment {
		if strings.HasPrefix(value, "PATH=") {
			environment[i] = "PATH=" + t.TempDir()
		}
	}
	command := exec.CommandContext(ctx, binary, "context", "--output", "json")
	command.Dir = project
	command.Env = environment
	cli, err := command.Output()
	if err != nil {
		t.Fatalf("CLI context: %v", err)
	}
	var cliResult struct {
		SchemaVersion string         `json:"schema_version"`
		Result        map[string]any `json:"result"`
	}
	if err := json.Unmarshal(cli, &cliResult); err != nil {
		t.Fatal(err)
	}
	if cliResult.SchemaVersion != "mulgae-command-result.v17" || strings.Contains(string(cli), project) {
		t.Fatalf("CLI context contract: %s", cli)
	}
	serverRoot := filepath.Join(base, "projectroot")
	if _, err := os.Stat(serverRoot); os.IsNotExist(err) {
		serverRoot = project
	} else if err != nil {
		t.Fatal(err)
	}
	server := exec.CommandContext(ctx, binary, "mcp", "--project-root", serverRoot)
	server.Dir = t.TempDir()
	server.Env = environment
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
	t.Cleanup(func() { _ = stdin.Close(); _ = server.Wait() })
	reader := bufio.NewReader(stdout)
	call := func(id int, method string, params any) map[string]any {
		t.Helper()
		request := map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}
		data, _ := json.Marshal(request)
		if _, err := fmt.Fprintln(stdin, string(data)); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadBytes('\n')
		if err != nil {
			t.Fatalf("MCP response: %v; %s", err, stderr.String())
		}
		var response map[string]any
		if err := json.Unmarshal(line, &response); err != nil {
			t.Fatal(err)
		}
		if response["error"] != nil {
			t.Fatalf("MCP error: %s", line)
		}
		return response["result"].(map[string]any)
	}
	call(1, "initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "context-fixture", "version": "1"}})
	if _, err := fmt.Fprintln(stdin, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); err != nil {
		t.Fatal(err)
	}
	response := call(2, "tools/call", map[string]any{"name": "get_context", "arguments": map[string]any{}})
	structured := response["structuredContent"].(map[string]any)
	if structured["outcome"] != "success" || !reflect.DeepEqual(structured["data"], cliResult.Result) {
		t.Fatalf("independent CLI/MCP context differs: %s / %#v", cli, structured)
	}
	if after := contextFixtureFiles(t, project); !reflect.DeepEqual(before, after) {
		t.Fatal("context wrote persistent state")
	}
	// Retargeting is forbidden, including through a replacement at the same path.
	moved := project + "-moved"
	if err := os.Rename(project, moved); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(moved) })
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	response = call(3, "tools/call", map[string]any{"name": "get_context", "arguments": map[string]any{}})
	structured = response["structuredContent"].(map[string]any)
	if structured["outcome"] != "error" || structured["data"] != nil {
		t.Fatalf("root drift admitted: %#v", structured)
	}
}

func contextFixtureFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		result[relative] = fmt.Sprintf("%v:%d:%d", info.Mode(), info.Size(), info.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
