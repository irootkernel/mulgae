//go:build darwin && arm64

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestIntegrationIsolatedReleaseFixtureVerifiedContent(t *testing.T) {
	source := repositoryRoot(t)
	binary := buildMulgaeBinary(t, source)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)
	patch := exec.Command("git", "diff", "HEAD", "--")
	patch.Dir = project
	patchBytes, err := patch.Output()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(patchBytes)
	target := "sha256:" + hex.EncodeToString(digest[:])
	claims := []any{}
	for _, item := range []struct {
		line  int
		quote string
	}{{1, "package review\n"}, {3, "const state = \"after\"\n"}} {
		claims = append(claims, map[string]any{"current": map[string]any{"path": "review.go", "line_start": item.line, "line_end": item.line, "side": "worktree", "quote": item.quote}})
	}
	wire, err := json.Marshal(map[string]any{"schema_version": "mulgae-provider-review-output.v1", "summary": "Fixture finding with two exact current excerpts.", "completeness": "complete", "limitations": []any{}, "findings": []any{map[string]any{"severity": "high", "title": "Fixture state change needs review", "description": "This isolated fixture exercises both evidence indices.", "evidence": claims, "recommendation": "Inspect both retained excerpts.", "confidence": "high"}}})
	if err != nil {
		t.Fatal(err)
	}
	body := "# logic role report\n\n" + strings.Repeat("Lossless report 🙂\tline\n", 2100) + "\n```json\n" + string(wire) + "\n```\n"
	nativeHome := integrationNativeHome(t, binary)
	providerDirectory := canonicalTestTempDir(t)
	providerLog := filepath.Join(canonicalTestTempDir(t), "provider.jsonl")
	bundle, node, launcher := fakeZCodeAppPaths(providerDirectory)
	buildFakeZCodeWithReport(t, source, node, launcher, providerLog, "success", "write", "", body)
	environment := isolatedMulgaeEnvWith(t, nativeHome, providerDirectory)
	initializeOfflineProvidersForRoles(t, binary, project, environment, "zcode", "logic", bundle)
	command := func(want int, args ...string) map[string]any {
		t.Helper()
		result := runMulgaeBinaryWithEnv(t, binary, project, environment, args...)
		if result.exitCode != want {

			t.Fatalf("%v: exit=%d stdout=%s stderr=%s", args, result.exitCode, result.stdout, result.stderr)
		}
		var envelope map[string]any
		if err := json.Unmarshal(result.stdout, &envelope); err != nil {
			t.Fatal(err)
		}
		return envelope["result"].(map[string]any)
	}
	preflight := command(0, "review", "--dirty", "--roles", "logic", "--preflight", "--output", "json")["preflight"].(map[string]any)
	if preflight["target"].(map[string]any)["sha256"] != target {
		t.Fatal("fixture patch differs from admitted target")
	}
	review := command(1, "review", "--dirty", "--roles", "logic", "--output", "json")
	run := review["run_id"].(string)
	beforeLog, err := os.ReadFile(providerLog)
	if err != nil {
		t.Fatal(err)
	}
	beforeFiles := contextFixtureFiles(t, project)
	inspection := command(0, "inspect", "--run", run, "--output", "json")
	if inspection["returned_count"] != float64(1) {
		t.Fatalf("missing fixture finding: %#v", inspection)
	}
	binding := inspection["receipt"].(map[string]any)["project_binding"].(string)
	receipt := inspection["publication_receipt"].(string)
	readCLI := func(base []string) []byte {
		t.Helper()
		args := append(append([]string{}, base...), "--expected-project-binding", binding, "--expected-publication-receipt", receipt, "--output", "json")
		var all []byte
		for {
			chunk := command(0, args...)
			if chunk["publication_receipt"] != receipt || chunk["offset"] != float64(len(all)) {
				t.Fatal("CLI receipt or offset drift")
			}
			part := []byte(chunk["content"].(string))
			if chunk["encoding"] == "base64" {
				part, err = base64.StdEncoding.DecodeString(string(part))
				if err != nil {
					t.Fatal(err)
				}
			}
			if len(part) > 16384 || chunk["returned_bytes"] != float64(len(part)) {
				t.Fatal("CLI chunk bound violated")
			}
			all = append(all, part...)
			if chunk["next_offset"] == nil {
				sum := sha256.Sum256(all)
				if chunk["total_bytes"] != float64(len(all)) || chunk["content_sha256"] != "sha256:"+hex.EncodeToString(sum[:]) {
					t.Fatal("CLI content digest mismatch")
				}
				break
			}
			args = append(append([]string{}, base...), "--offset", strconv.FormatInt(int64(chunk["next_offset"].(float64)), 10), "--expected-project-binding", binding, "--expected-publication-receipt", receipt, "--expected-content-sha256", chunk["content_sha256"].(string), "--output", "json")
		}
		return all
	}
	rendered := readCLI([]string{"read-report", "--run", run})
	if original := readCLI([]string{"read-report", "--run", run, "--role", "logic"}); !bytes.Equal(original, []byte(body)) {
		t.Fatal("original role report changed")
	}
	finding := inspection["findings"].([]any)[0].(map[string]any)
	id := finding["id"].(string)
	evidence := finding["evidence"].([]any)
	if len(evidence) != 2 {
		t.Fatalf("indices=%d", len(evidence))
	}
	excerpts := make([][]byte, 2)
	for i := range evidence {
		excerpts[i] = readCLI([]string{"excerpt", "--run", run, "--finding", id, "--current-target-sha256", target, "--evidence-index", strconv.Itoa(i)})
	}
	if !(bytes.Equal(excerpts[0], []byte("package review\n")) && bytes.Equal(excerpts[1], []byte("const state = \"after\"\n")) || bytes.Equal(excerpts[1], []byte("package review\n")) && bytes.Equal(excerpts[0], []byte("const state = \"after\"\n"))) {
		t.Fatal("evidence bytes changed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	server := exec.CommandContext(ctx, binary, "mcp", "--project-root", project)
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
	defer func() {
		_ = stdin.Close()
		if err := server.Wait(); err != nil {
			t.Errorf("MCP: %v %s", err, stderr.String())
		}
	}()
	reader := bufio.NewReader(stdout)
	requestID := 0
	call := func(method string, params any) map[string]any {
		t.Helper()
		requestID++
		raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": requestID, "method": method, "params": params})
		if _, err := fmt.Fprintln(stdin, string(raw)); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
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
	call("initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "verified-content-fixture", "version": "1"}})
	if _, err := fmt.Fprintln(stdin, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); err != nil {
		t.Fatal(err)
	}
	readMCP := func(uri string) []byte {
		t.Helper()
		var all []byte
		for {
			content := call("resources/read", map[string]any{"uri": uri})["contents"].([]any)[0].(map[string]any)
			meta := content["_meta"].(map[string]any)
			if meta["publication_receipt"] != receipt || meta["project_binding"] != binding || meta["offset"] != float64(len(all)) {
				t.Fatal("MCP receipt or offset drift")
			}
			var part []byte
			if text, ok := content["text"].(string); ok {
				part = []byte(text)
			} else {
				part, err = base64.StdEncoding.DecodeString(content["blob"].(string))
				if err != nil {
					t.Fatal(err)
				}
			}
			if len(part) > 16384 {
				t.Fatal("MCP chunk too large")
			}
			all = append(all, part...)
			if meta["io.mulgae/nextURI"] == nil {
				sum := sha256.Sum256(all)
				if meta["content_sha256"] != "sha256:"+hex.EncodeToString(sum[:]) || meta["total_bytes"] != float64(len(all)) {
					t.Fatal("MCP digest mismatch")
				}
				break
			}
			uri = meta["io.mulgae/nextURI"].(string)
		}
		return all
	}
	// Literal consumer grammar is intentionally independent of producer URI helpers.
	renderURI := "mulgae://runs/" + run + "/report?project_binding=" + strings.ReplaceAll(binding, ":", "%3A") + "&publication_receipt=" + strings.ReplaceAll(receipt, ":", "%3A")
	if !bytes.Equal(readMCP(renderURI), rendered) {
		t.Fatal("rendered CLI/MCP bytes differ")
	}
	roleURI := inspection["role_reports"].([]any)[0].(map[string]any)["uri"].(string)
	if !bytes.Equal(readMCP(roleURI), []byte(body)) {
		t.Fatal("MCP role report changed")
	}
	for i, item := range evidence {
		if !bytes.Equal(readMCP(item.(map[string]any)["uri"].(string)), excerpts[i]) {
			t.Fatal("indexed CLI/MCP evidence differs")
		}
	}
	afterLog, err := os.ReadFile(providerLog)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeLog, afterLog) || !reflect.DeepEqual(beforeFiles, contextFixtureFiles(t, project)) {
		t.Fatal("read invoked provider or wrote persistent files")
	}
}
