//go:build mcpclientcheck && requirementsclientcheck

package mcpclientcheck_test

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type requirementsFixture struct {
	Project string `json:"project_root"`
	Run     string `json:"run_id"`
	Binding string `json:"project_binding"`
	Receipt string `json:"publication_receipt"`
	Pages   []map[string]any
}

func requirementsCLI(t *testing.T, binary, project string, args ...string) map[string]any {
	t.Helper()
	output := run(t, binary, append(args, "--output", "json"), project, nil)
	var envelope struct {
		Schema string         `json:"schema_version"`
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal([]byte(output), &envelope); err != nil || envelope.Schema != "mulgae-command-result.v24" || envelope.Result == nil {
		t.Fatal("candidate CLI did not return the current public result contract")
	}
	return envelope.Result
}

func requirementsClientFixture(t *testing.T, binary string) requirementsFixture {
	t.Helper()
	var fixture requirementsFixture
	if path := os.Getenv("MULGAE_MCP_REQUIREMENTS_FIXTURE"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(raw, &fixture) != nil || fixture.Project == "" || fixture.Run == "" {
			t.Fatal("invalid existing published client fixture")
		}
	} else {
		fixture.Project = newGitProject(t)
		input := `{"schema_version":"mulgae-requirements-input.v1","requirements":[{"id":"CLIENT-A","text":"Check the selected target.","acceptance_criteria":["Keep unavailable evaluation explicit."],"owner_role":"logic"},{"id":"CLIENT-B","text":"Preserve every selected item.","acceptance_criteria":["Do not infer satisfaction from no change."],"owner_role":"logic"}]}`
		if err := os.WriteFile(filepath.Join(fixture.Project, "requirements.json"), []byte(input), 0o600); err != nil {
			t.Fatal(err)
		}
		requirementsCLI(t, binary, fixture.Project, "init", "--providers", "zcode", "--roles", "logic")
		fixture.Binding = requirementsCLI(t, binary, fixture.Project, "context")["project_binding"].(string)
		created := requirementsCLI(t, binary, fixture.Project, "review", "--stage", "--requirements", "requirements.json", "--expected-project-binding", fixture.Binding)
		fixture.Run = created["run_id"].(string)
	}
	binding := requirementsCLI(t, binary, fixture.Project, "context")["project_binding"].(string)
	if fixture.Binding != binding {
		t.Fatal("existing fixture project binding changed")
	}
	args := []string{"inspect", "--run", fixture.Run, "--severity", "low", "--requirements-limit", "1", "--expected-project-binding", fixture.Binding}
	if fixture.Receipt != "" {
		args = append(args, "--expected-publication-receipt", fixture.Receipt)
	}
	for {
		page := requirementsCLI(t, binary, fixture.Project, args...)
		receipt := page["publication_receipt"].(string)
		if fixture.Receipt != "" && fixture.Receipt != receipt {
			t.Fatal("existing fixture receipt changed")
		}
		fixture.Receipt = receipt
		fixture.Pages = append(fixture.Pages, page)
		next := page["requirements"].(map[string]any)["next_cursor"]
		if next == nil {
			break
		}
		args = []string{"inspect", "--run", fixture.Run, "--severity", "low", "--requirements-limit", "1", "--requirements-cursor", next.(string), "--expected-project-binding", fixture.Binding, "--expected-publication-receipt", fixture.Receipt}
	}
	if len(fixture.Pages) < 2 {
		t.Fatal("client fixture must exercise requirements continuation")
	}
	return fixture
}

func clientBinaryDigest(t *testing.T, binary string) string {
	t.Helper()
	file, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("sha256:%x", digest.Sum(nil))
}

func writeClientProof(t *testing.T, name string, proof map[string]any) {
	t.Helper()
	if dir := os.Getenv("MULGAE_MCP_CLIENT_EVIDENCE_DIR"); dir != "" {
		if !filepath.IsAbs(dir) {
			t.Fatal("client evidence directory must be absolute")
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		raw, err := json.MarshalIndent(proof, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(filepath.Join(dir, name+".json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.Write(append(raw, '\n'))
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatal("client proof persistence failed")
		}
	}
}

func TestCodexReadsVerifiedRequirementsThroughNativeMCP(t *testing.T) {
	binary, codex := requiredExecutable(t, mulgaeBinaryEnv), requiredExecutable(t, codexBinaryEnv)
	fixture := requirementsClientFixture(t, binary)
	version := strings.TrimSpace(run(t, codex, []string{"--version"}, fixture.Project, nil))
	server := fmt.Sprintf("{mulgae={command=%s,args=[%s,%s,%s],cwd=%s,required=true,startup_timeout_sec=30,tool_timeout_sec=%d}}", strconv.Quote(binary), strconv.Quote("mcp"), strconv.Quote("--project-root"), strconv.Quote(fixture.Project), strconv.Quote(fixture.Project), toolTimeoutSec)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, codex, "app-server", "--stdio", "-c", "mcp_servers="+server)
	command.Dir = fixture.Project
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var diagnostics limitedBuffer
	command.Stderr = &diagnostics
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = input.Close()
		if err := command.Wait(); err != nil {
			t.Errorf("Codex native client exit: %v; diagnostic_bytes=%d", err, diagnostics.Len())
		}
	}()
	reader := bufio.NewScanner(output)
	reader.Buffer(make([]byte, 4096), maxOutputBytes)
	id := 0
	methods := []string{}
	call := func(method string, params any) map[string]any {
		t.Helper()
		id++
		methods = append(methods, method)
		if err := json.NewEncoder(input).Encode(map[string]any{"id": id, "method": method, "params": params}); err != nil {
			t.Fatal(err)
		}
		for reader.Scan() {
			var message map[string]any
			if json.Unmarshal(reader.Bytes(), &message) != nil {
				t.Fatal("Codex emitted invalid native protocol JSON")
			}
			if message["method"] != nil {
				if message["id"] != nil {
					t.Fatal("unexpected native client interaction request")
				}
				continue
			}
			if message["id"] != float64(id) {
				t.Fatal("Codex native response identity changed")
			}
			if message["error"] != nil {
				t.Fatalf("Codex native method %s failed", method)
			}
			return message["result"].(map[string]any)
		}
		t.Fatalf("Codex native protocol ended during %s: %v", method, reader.Err())
		return nil
	}
	call("initialize", map[string]any{"clientInfo": map[string]string{"name": "mulgae-client-check", "version": "1"}})
	if err := json.NewEncoder(input).Encode(map[string]any{"method": "initialized", "params": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	thread := call("thread/start", map[string]any{"cwd": fixture.Project, "ephemeral": true, "approvalPolicy": "never", "sandbox": "read-only"})
	threadID := thread["thread"].(map[string]any)["id"].(string)
	call("mcpServerStatus/list", map[string]any{"threadId": threadID, "serverName": "mulgae", "detail": "full"})
	tool := func(name string, arguments map[string]any) map[string]any {
		t.Helper()
		response := call("mcpServer/tool/call", map[string]any{"threadId": threadID, "server": "mulgae", "tool": name, "arguments": arguments})
		structured, ok := response["structuredContent"].(map[string]any)
		if !ok || response["isError"] == true || structured["outcome"] != "success" {
			t.Fatalf("Codex native MCP %s did not return a successful public result", name)
		}
		return structured["data"].(map[string]any)
	}
	context := tool("get_context", map[string]any{})
	if context["project_binding"] != fixture.Binding || context["capabilities"].(map[string]any)["requirements_assessment"] != "v1" {
		t.Fatal("Codex native client connected to wrong requirements capability/root")
	}
	cursor := ""
	resources := 0
	verifiedItems := []map[string]any{}
	for _, expected := range fixture.Pages {
		args := map[string]any{"run_id": fixture.Run, "minimum_severity": "low", "requirements_limit": 1, "expected_project_binding": fixture.Binding, "expected_publication_receipt": fixture.Receipt}
		if cursor != "" {
			args["requirements_cursor"] = cursor
		}
		page := tool("inspect_review", args)
		if page["publication_receipt"] != fixture.Receipt || !reflect.DeepEqual(page["requirements"], expected["requirements"]) {
			t.Fatal("Codex native public requirements page differs from independent CLI")
		}
		for requirementID, link := range page["requirement_content_uris"].(map[string]any) {
			expectedItem := expected["requirements"].(map[string]any)["items"].([]any)[0].(map[string]any)
			if expectedItem["requirement_id"] != requirementID {
				t.Fatal("independent CLI metadata row does not bind the resource")
			}
			uri := link.(string)
			var content []byte
			for {
				result := call("mcpServer/resource/read", map[string]any{"threadId": threadID, "server": "mulgae", "uri": uri})
				resource := result["contents"].([]any)[0].(map[string]any)
				meta := resource["_meta"].(map[string]any)
				part := []byte(resource["text"].(string))
				if meta["publication_receipt"] != fixture.Receipt || meta["requirement_id"] != requirementID || meta["offset"] != float64(len(content)) || len(part) > 16384 {
					t.Fatal("Codex native requirement resource lost receipt/chunk identity")
				}
				content = append(content, part...)
				if next := meta["io.mulgae/nextURI"]; next != nil {
					uri = next.(string)
					continue
				}
				var item map[string]any
				sum := sha256.Sum256(content)
				if json.Unmarshal(content, &item) != nil || item["requirement_id"] != requirementID || meta["content_sha256"] != fmt.Sprintf("sha256:%x", sum) || expectedItem["content_sha256"] != meta["content_sha256"] || expectedItem["content_byte_length"] != float64(len(content)) || meta["total_bytes"] != float64(len(content)) {
					t.Fatal("Codex native complete requirement content is invalid")
				}
				verifiedItems = append(verifiedItems, map[string]any{"requirement_id": requirementID, "content_sha256": meta["content_sha256"], "content_byte_length": len(content)})
				break
			}
			resources++
		}
		next := page["requirements"].(map[string]any)["next_cursor"]
		cursor = ""
		if next != nil {
			cursor = next.(string)
		}
	}
	proof := map[string]any{"client": version, "binary_sha256": clientBinaryDigest(t, binary), "project_binding": fixture.Binding, "run_id": fixture.Run, "publication_receipt": fixture.Receipt, "requirements": fixture.Pages[0]["requirements"], "pages_read": len(fixture.Pages), "complete_resources_read": resources, "verified_items": verifiedItems, "independent_cli_content_hash_and_length_bound": true, "actual_native_methods": methods, "model_turns": 0, "mulgae_provider_reviews_started": 0, "long_await_or_release_lifecycle_proven": false}
	writeClientProof(t, "codex-requirements", proof)
	t.Logf("Codex native MCP requirements pages=%d complete_resources=%d model_turns=0 provider_reviews=0", len(fixture.Pages), resources)
}
