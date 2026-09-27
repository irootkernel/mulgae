//go:build darwin && arm64

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// One binary and one attached server carry independent consumer expectations
// from root lookup through a provider-free run and a recovered composite.
func TestIntegrationIsolatedReleaseFixtureVerifiedWorkflow(t *testing.T) {
	source := repositoryRoot(t)
	binary := buildMulgaeBinary(t, source)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)
	providers := canonicalTestTempDir(t)
	logPath := filepath.Join(canonicalTestTempDir(t), "provider.jsonl")
	bundle, node, launcher := fakeZCodeAppPaths(providers)
	buildFakeZCodeWithReport(t, source, node, launcher, logPath, "fail_first_maintainability", "write", "", compositeEvidenceReport())
	environment := isolatedMulgaeEnvWith(t, integrationNativeHome(t, binary), providers)
	initializeOfflineProvidersForRoles(t, binary, project, environment, "zcode", "logic,maintainability", bundle)
	decode := func(raw []byte) verifiedConsumerResult {
		t.Helper()
		value, err := decodeVerifiedConsumerResult(raw)
		if err != nil {
			t.Fatalf("consumer data: %v: %s", err, raw)
		}
		return value
	}
	cli := func(want int, args ...string) json.RawMessage {
		t.Helper()
		result := runMulgaeBinaryWithEnv(t, binary, project, environment, append(args, "--output", "json")...)
		if result.exitCode != want {
			t.Fatalf("CLI %v: exit %d: %s %s", args, result.exitCode, result.stdout, result.stderr)
		}
		data, err := decodeVerifiedConsumerEnvelope(result.stdout, "cli", args[0], false)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	expectedContext := decode(cli(0, "context"))
	if !consumerDigest(expectedContext.ProjectBinding) {
		t.Fatal("CLI context did not establish an independent binding")
	}
	for _, capability := range []string{"project_binding", "execution_guard", "capture_identity", "inspection", "report_content", "indexed_evidence", "composite_evidence"} {
		if expectedContext.Capabilities[capability] != "v1" {
			t.Fatalf("required capability %s unavailable", capability)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
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
			t.Errorf("attached MCP: %v: %s", err, stderr.String())
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
			t.Fatalf("MCP response: %v: %s", err, stderr.String())
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
			t.Fatalf("MCP protocol result: %s", line)
		}
		return response.Result
	}
	rpc("initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "frozen-verified-consumer", "version": "1"}})
	if _, err := fmt.Fprintln(stdin, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); err != nil {
		t.Fatal(err)
	}
	toolCalls := map[string]int{}
	tool := func(name string, arguments map[string]any) json.RawMessage {
		t.Helper()
		toolCalls[name]++
		var result struct {
			Structured json.RawMessage `json:"structuredContent"`
		}
		if err := json.Unmarshal(rpc("tools/call", map[string]any{"name": name, "arguments": arguments}), &result); err != nil {
			t.Fatal(err)
		}
		data, err := decodeVerifiedConsumerEnvelope(result.Structured, "mcp", name, false)
		if err != nil {
			t.Fatalf("MCP consumer %s: %v: %s", name, err, result.Structured)
		}
		return data
	}
	if actual := decode(tool("get_context", map[string]any{})); !reflect.DeepEqual(actual, expectedContext) {
		t.Fatal("independent CLI root differs from attached MCP root")
	}
	preflight := func(targetArgs []string, objective string) verifiedConsumerResult {
		t.Helper()
		args := append(append([]string{"review"}, targetArgs...), "--roles", "logic,maintainability", "--preflight", "--expected-project-binding", expectedContext.ProjectBinding)
		if objective != "" {
			args = append(args, "--objective", objective)
		}
		var result struct {
			Preflight json.RawMessage `json:"preflight"`
		}
		if err := json.Unmarshal(cli(0, args...), &result); err != nil {
			t.Fatal(err)
		}
		value := decode(result.Preflight)
		if value.ProjectBinding != expectedContext.ProjectBinding || value.RequestReceipt.ProjectBinding != expectedContext.ProjectBinding || !consumerDigest(value.CaptureIdentity) || !consumerDigest(value.RequestReceipt.RequestDigest) || value.RequestReceipt.SchemaVersion != "mulgae-request-receipt.v1" || value.RequestReceipt.CaptureIdentity != value.CaptureIdentity {
			t.Fatal("preflight is not complete guarded authority")
		}
		return value
	}
	baselineLog, _ := os.ReadFile(logPath)
	stage := preflight([]string{"--stage"}, "")
	noChange := decode(cli(0, "review", "--stage", "--roles", "logic,maintainability", "--expected-project-binding", expectedContext.ProjectBinding, "--expected-request-digest", stage.RequestReceipt.RequestDigest))
	if !noChange.Guarded || noChange.CaptureIdentity != stage.CaptureIdentity || noChange.RequestDigest != stage.RequestReceipt.RequestDigest {
		t.Fatal("no-change lost request provenance")
	}
	noChangeInspection := decode(tool("inspect_review", map[string]any{"run_id": noChange.RunID, "expected_project_binding": expectedContext.ProjectBinding}))
	if noChangeInspection.CaptureAvailability != "verified" || noChangeInspection.CaptureIdentity != stage.CaptureIdentity || !consumerDigest(noChangeInspection.PublicationReceipt) || noChangeInspection.FindingCount != 0 {
		t.Fatal("no-change lost retained capture provenance")
	}
	if after, _ := os.ReadFile(logPath); !bytes.Equal(after, baselineLog) {
		t.Fatal("context, preflight, or no-change invoked provider")
	}

	// A request-only objective differs over identical capture bytes.
	dirty := preflight([]string{"--dirty"}, "")
	objective := preflight([]string{"--dirty"}, "Review immutable support.")
	if dirty.CaptureIdentity != objective.CaptureIdentity || dirty.RequestReceipt.RequestDigest == objective.RequestReceipt.RequestDigest {
		t.Fatal("consumer conflated capture and request identity")
	}
	// The same dirty patch over changed committed support is a different capture.
	// This also changes Git identity; isolated component proofs belong to unit tests.
	beforeSupport := dirty
	linkedPath := filepath.Join(project, "docs", "linked.md")
	linked, err := os.ReadFile(linkedPath)
	if err != nil {
		t.Fatal(err)
	}
	mustWriteTestFile(t, linkedPath, append(append([]byte{}, linked...), []byte("Additional captured support.\n")...))
	runTestCommand(t, project, "git", "add", "docs/linked.md")
	runTestCommand(t, project, "git", "-c", "user.name=Mulgae E2E", "-c", "user.email=mulgae-e2e@example.invalid", "commit", "-m", "change fixture support")
	afterSupport := preflight([]string{"--dirty"}, "")
	if beforeSupport.Target.SHA256 != afterSupport.Target.SHA256 || beforeSupport.CaptureIdentity == afterSupport.CaptureIdentity {
		t.Fatal("consumer confused equal patch with equal complete capture")
	}
	dirty = afterSupport
	arguments := map[string]any{"target": map[string]any{"kind": "dirty"}, "roles": []string{"logic", "maintainability"}, "expected_project_binding": expectedContext.ProjectBinding}
	mcpPreflight := decode(tool("preflight_review", arguments))
	if mcpPreflight.RequestReceipt != dirty.RequestReceipt || mcpPreflight.CaptureIdentity != dirty.CaptureIdentity {
		t.Fatal("CLI/MCP admitted plans differ")
	}
	arguments["expected_request_digest"] = dirty.RequestReceipt.RequestDigest
	started := decode(tool("start_review", arguments))
	if started.InvocationID == "" {
		t.Fatal("start returned no invocation identity")
	}
	terminal := decode(tool("await_review", map[string]any{"invocation_id": started.InvocationID}))
	if terminal.ProjectBinding != expectedContext.ProjectBinding || !terminal.Guarded || terminal.RequestDigest != dirty.RequestReceipt.RequestDigest || terminal.CaptureIdentity != dirty.CaptureIdentity || terminal.TerminalExitCode != 4 {
		t.Fatalf("guarded incomplete root: %+v", terminal)
	}
	recovered := decode(cli(0, "rerun", "--run", terminal.RunID, "--role", "maintainability", "--provider", "zcode-maintainability"))
	composite := decode(tool("compose_review", map[string]any{"root_run_id": terminal.RunID, "recovery_run_ids": []string{recovered.RunID}}))
	cliInspection := decode(cli(0, "inspect", "--run", composite.RunID, "--expected-project-binding", expectedContext.ProjectBinding))
	mcpInspection := decode(tool("inspect_review", map[string]any{"run_id": composite.RunID, "expected_project_binding": expectedContext.ProjectBinding, "expected_publication_receipt": cliInspection.PublicationReceipt}))
	if !reflect.DeepEqual(cliInspection, mcpInspection) || cliInspection.CaptureIdentity != dirty.CaptureIdentity || !consumerDigest(cliInspection.PublicationReceipt) || cliInspection.FindingCount != 2 || cliInspection.ReturnedCount != 2 || len(cliInspection.Findings) != 2 || len(cliInspection.RoleReports) != 2 {
		t.Fatal("composite inspection is not coherent across consumers")
	}

	readCLI := func(base ...string) []byte {
		t.Helper()
		args := append(append([]string{}, base...), "--expected-project-binding", expectedContext.ProjectBinding, "--expected-publication-receipt", cliInspection.PublicationReceipt)
		var content []byte
		for {
			chunk := decode(cli(0, args...))
			if chunk.Offset != int64(len(content)) || chunk.PublicationReceipt != cliInspection.PublicationReceipt || chunk.Encoding != "utf8" || chunk.ReturnedBytes != int64(len(chunk.Content)) || chunk.ReturnedBytes > 16384 {
				t.Fatal("CLI content chunk binding failed")
			}
			content = append(content, chunk.Content...)
			if chunk.NextOffset == nil {
				verifyConsumerContent(t, content, chunk.ContentSHA256, chunk.TotalBytes)
				return content
			}
			if *chunk.NextOffset != int64(len(content)) || chunk.ReturnedBytes == 0 {
				t.Fatal("CLI continuation did not advance")
			}
			args = append(append([]string{}, base...), "--expected-project-binding", expectedContext.ProjectBinding, "--expected-publication-receipt", cliInspection.PublicationReceipt, "--expected-content-sha256", chunk.ContentSHA256, "--offset", strconv.FormatInt(*chunk.NextOffset, 10))
		}
	}
	readMCP := func(uri string) []byte {
		t.Helper()
		var content []byte
		for {
			var response struct {
				Contents []struct {
					Text string          `json:"text"`
					Meta json.RawMessage `json:"_meta"`
				} `json:"contents"`
			}
			if err := json.Unmarshal(rpc("resources/read", map[string]any{"uri": uri}), &response); err != nil {
				t.Fatal(err)
			}
			if len(response.Contents) != 1 {
				t.Fatal("MCP resource cardinality")
			}
			part := response.Contents[0]
			chunk := decode(part.Meta)
			if chunk.ProjectBinding != expectedContext.ProjectBinding || chunk.PublicationReceipt != cliInspection.PublicationReceipt || chunk.Offset != int64(len(content)) || chunk.ReturnedBytes != int64(len(part.Text)) || chunk.ReturnedBytes > 16384 {
				t.Fatal("MCP content chunk binding failed")
			}
			content = append(content, part.Text...)
			var continuation struct {
				NextURI string `json:"io.mulgae/nextURI"`
			}
			if err := json.Unmarshal(part.Meta, &continuation); err != nil {
				t.Fatal(err)
			}
			if continuation.NextURI == "" {
				verifyConsumerContent(t, content, chunk.ContentSHA256, chunk.TotalBytes)
				return content
			}
			if chunk.ReturnedBytes == 0 {
				t.Fatal("MCP continuation did not advance")
			}
			uri = continuation.NextURI
		}
	}
	readLog, _ := os.ReadFile(logPath)
	rendered := readCLI("read-report", "--run", composite.RunID)
	uri := "mulgae://runs/" + composite.RunID + "/report?project_binding=" + url.QueryEscape(expectedContext.ProjectBinding) + "&publication_receipt=" + url.QueryEscape(cliInspection.PublicationReceipt)
	if len(rendered) == 0 || !bytes.Equal(rendered, readMCP(uri)) {
		t.Fatal("complete rendered report differs between consumers")
	}
	for _, report := range cliInspection.RoleReports {
		expected := []byte(strings.ReplaceAll(compositeEvidenceReport(), "__ROLE__", report.Role))
		if !bytes.Equal(readCLI("read-report", "--run", composite.RunID, "--role", report.Role), expected) || !bytes.Equal(readMCP(report.URI), expected) {
			t.Fatal("complete original role report changed")
		}
	}
	for _, finding := range cliInspection.Findings {
		if !bytes.Equal(readCLI("read-finding", "--run", composite.RunID, "--finding", finding.ID), readMCP(finding.DetailURI)) || len(finding.Evidence) != 2 {
			t.Fatal("composite finding detail or evidence inventory differs")
		}
		for i, item := range finding.Evidence {
			if item.Index != i || !bytes.Equal(readCLI("excerpt", "--run", composite.RunID, "--finding", finding.ID, "--current-target-sha256", dirty.Target.SHA256, "--evidence-index", strconv.Itoa(i)), readMCP(item.URI)) {
				t.Fatal("composite evidence index differs between consumers")
			}
		}
	}
	if after, _ := os.ReadFile(logPath); !bytes.Equal(after, readLog) {
		t.Fatal("read-only consumers invoked a provider")
	}
	if toolCalls["start_review"] != 1 || toolCalls["await_review"] != 1 || toolCalls["get_review_execution"] != 0 {
		t.Fatal("workflow repeated start/await or polled execution")
	}
}

func verifyConsumerContent(t *testing.T, content []byte, digest string, size int64) {
	t.Helper()
	sum := sha256.Sum256(content)
	if size != int64(len(content)) || digest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("consumer did not read exact complete content")
	}
}
