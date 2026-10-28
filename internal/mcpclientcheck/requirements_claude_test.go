//go:build mcpclientcheck && requirementsclientcheck

package mcpclientcheck_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestClaudeReadsVerifiedRequirementsThroughMCP(t *testing.T) {
	binary, claude := requiredExecutable(t, mulgaeBinaryEnv), requiredExecutable(t, claudeBinaryEnv)
	fixture := requirementsClientFixture(t, binary)
	version := strings.TrimSpace(run(t, claude, []string{"--version"}, fixture.Project, nil))
	config, err := json.Marshal(map[string]any{"mcpServers": map[string]any{"mulgae": map[string]any{"command": binary, "args": []string{"mcp", "--project-root", fixture.Project}, "timeout": toolTimeoutMS}}})
	if err != nil {
		t.Fatal(err)
	}
	prompt := fmt.Sprintf("Use only the Mulgae MCP public read tools get_context, inspect_review and list_findings. Do not use files, commands, agents, review/start/cancel/preflight or any other tool. First call get_context and verify project_binding is %s. Then call inspect_review with run_id=%s, expected_project_binding=%s, expected_publication_receipt=%s, minimum_severity=low and requirements_limit=1. Read every selected requirement by following requirements.next_cursor through list_findings, keeping those exact guards/limit/severity and supplying requirements_cursor. Stop only at next_cursor=null. Do not repeat a page. These are provider-free reads of an existing publication; never start a review. After all %d pages, briefly report IDs, origins and global selected/evaluated counts.", fixture.Binding, fixture.Run, fixture.Binding, fixture.Receipt, len(fixture.Pages))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	arguments := []string{"-p", prompt, "--output-format", "stream-json", "--verbose", "--no-session-persistence", "--strict-mcp-config", "--mcp-config", string(config), "--tools", "", "--allowedTools", "mcp__mulgae__get_context", "mcp__mulgae__inspect_review", "mcp__mulgae__list_findings", "--permission-prompts", "none", "--disable-slash-commands"}
	command := exec.CommandContext(ctx, claude, arguments...)
	command.Dir = fixture.Project
	var output, diagnostics limitedBuffer
	command.Stdout, command.Stderr = &output, &diagnostics
	started := time.Now().UTC()
	runErr := command.Run()
	ended := time.Now().UTC()
	proof := map[string]any{"client": version, "binary_sha256": clientBinaryDigest(t, binary), "project_binding": fixture.Binding, "run_id": fixture.Run, "publication_receipt": fixture.Receipt, "started_at": started.Format(time.RFC3339Nano), "ended_at": ended.Format(time.RFC3339Nano), "native_cli_invocations": 1, "model_or_effort_override": false, "mulgae_provider_reviews_started": 0, "native_resource_reads": 0, "native_resources_certified": false, "long_await_or_release_lifecycle_proven": false, "event_timing": "Native event order captured; no model-idle/long-await claim.", "stdout_sha256": fmt.Sprintf("sha256:%x", sha256.Sum256(output.Bytes())), "stderr_bytes": diagnostics.Len(), "success": false}
	defer func() { writeClientProof(t, "claude-requirements", proof) }()
	type toolUse struct {
		Name string
		Args map[string]any
	}
	uses := map[string]toolUse{}
	results := map[string]map[string]any{}
	order := []string{}
	inventory := []map[string]any{}
	terminalSuccess := false
	reader := bufio.NewScanner(bytes.NewReader(output.Bytes()))
	reader.Buffer(make([]byte, 4096), maxOutputBytes)
	for reader.Scan() {
		var event map[string]any
		if json.Unmarshal(reader.Bytes(), &event) != nil {
			t.Fatal("Claude did not emit complete native JSON events")
		}
		entry := map[string]any{"type": event["type"], "subtype": event["subtype"]}
		if event["type"] == "system" && event["subtype"] == "init" {
			proof["observed_model"] = event["model"]
			proof["client_session_id"] = event["session_id"]
		}
		if event["type"] == "result" {
			terminalSuccess = event["subtype"] == "success" && event["is_error"] != true
			proof["native_result_subtype"], proof["observed_model_turns"] = event["subtype"], event["num_turns"]
		}
		if message, ok := event["message"].(map[string]any); ok {
			if content, ok := message["content"].([]any); ok {
				types := []string{}
				for _, value := range content {
					block, ok := value.(map[string]any)
					if !ok {
						continue
					}
					kind, _ := block["type"].(string)
					types = append(types, kind)
					switch kind {
					case "tool_use":
						id, _ := block["id"].(string)
						name, _ := block["name"].(string)
						if name != "mcp__mulgae__get_context" && name != "mcp__mulgae__inspect_review" && name != "mcp__mulgae__list_findings" {
							t.Fatal("Claude requested a tool outside the authorized public-read set")
						}
						args, _ := block["input"].(map[string]any)
						uses[id] = toolUse{name, args}
						order = append(order, id)
					case "tool_result":
						id, _ := block["tool_use_id"].(string)
						if block["is_error"] == true {
							continue
						}
						texts := []string{}
						if text, ok := block["content"].(string); ok {
							texts = append(texts, text)
						}
						if parts, ok := block["content"].([]any); ok {
							for _, part := range parts {
								if text, ok := part.(map[string]any)["text"].(string); ok {
									texts = append(texts, text)
								}
							}
						}
						for _, text := range texts {
							var result map[string]any
							if json.Unmarshal([]byte(text), &result) == nil && result["schema_version"] == "mulgae-mcp-tool-result.v1" && result["outcome"] == "success" {
								results[id] = result
							}
						}
					}
				}
				entry["block_types"] = types
			}
		}
		inventory = append(inventory, entry)
	}
	proof["event_inventory"], proof["actual_tool_uses"], proof["parsed_public_results"] = inventory, len(uses), len(results)
	if runErr != nil || reader.Err() != nil || !terminalSuccess {
		t.Fatalf("Claude client invocation did not complete successfully: exit=%v stream_error=%v result=%v stderr_bytes=%d", runErr, reader.Err(), proof["native_result_subtype"], diagnostics.Len())
	}
	if len(order) != len(fixture.Pages)+1 || len(results) != len(order) {
		t.Fatal("Claude native events did not prove every public call/result")
	}
	contextUse := uses[order[0]]
	contextData := results[order[0]]["data"].(map[string]any)
	if contextUse.Name != "mcp__mulgae__get_context" || contextData["project_binding"] != fixture.Binding || contextData["capabilities"].(map[string]any)["requirements_assessment"] != "v1" {
		t.Fatal("Claude did not independently verify the requested root/capability")
	}
	cursor := ""
	observed := []map[string]any{}
	for index, expected := range fixture.Pages {
		use := uses[order[index+1]]
		result := results[order[index+1]]
		data := result["data"].(map[string]any)
		inputCursor, _ := use.Args["requirements_cursor"].(string)
		if use.Args["run_id"] != fixture.Run || use.Args["expected_project_binding"] != fixture.Binding || use.Args["expected_publication_receipt"] != fixture.Receipt || use.Args["requirements_limit"] != float64(1) || use.Args["minimum_severity"] != "low" || inputCursor != cursor || data["publication_receipt"] != fixture.Receipt || !reflect.DeepEqual(data["requirements"], expected["requirements"]) {
			t.Fatal("Claude model/client public requirements call lost guards, page order or global counts/origins")
		}
		if result["tool"] != strings.TrimPrefix(use.Name, "mcp__mulgae__") {
			t.Fatal("Claude native result does not belong to its observed tool call")
		}
		observed = append(observed, map[string]any{"tool": use.Name, "arguments": use.Args, "requirements": data["requirements"]})
		next := data["requirements"].(map[string]any)["next_cursor"]
		cursor = ""
		if next != nil {
			cursor = next.(string)
		}
	}
	proof["observed_public_pages"], proof["pages_read"], proof["success"] = observed, len(observed), true
	t.Logf("Claude model/client native MCP requirements pages=%d public_calls=%d provider_reviews=0 resource_proof=false", len(observed), len(order))
}
