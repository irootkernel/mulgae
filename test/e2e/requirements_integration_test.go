//go:build darwin && arm64

package e2e

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

func TestIntegrationIsolatedReleaseFixtureRequirements(t *testing.T) {
	source := repositoryRoot(t)
	binary := buildMulgaeBinary(t, source)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)
	mustWriteTestFile(t, filepath.Join(project, "review.go"), []byte("package review\n\nconst state = \"after\"\n\n// Next returns the following integer.\nfunc Next(value int) int { return value - 1 }\n"))
	inputs := []any{}
	for _, id := range []string{"A", "B", "C", "D", "E"} {
		inputs = append(inputs, map[string]any{"id": id, "text": "PRIVATE_INVOCATION_" + id, "acceptance_criteria": []string{"Preserve the selected implementation."}, "owner_role": "logic"})
	}
	input, _ := json.Marshal(map[string]any{"schema_version": "mulgae-requirements-input.v1", "requirements": inputs})
	inputPath := filepath.Join(project, "requirements.json")
	if err := os.WriteFile(inputPath, input, 0644); err != nil {
		t.Fatal(err)
	}
	rationale := strings.Repeat("Retained rationale 🙂\n", 1800)
	answers := []any{}
	for i, verdict := range []string{"met", "unmet", "partially_met", "unverified"} {
		reason := ""
		if verdict == "unverified" {
			reason = "insufficient_evidence"
		}
		evidence := []any{}
		if verdict == "met" || verdict == "partially_met" {
			evidence = append(evidence, map[string]any{"current": map[string]any{"path": "review.go", "line_start": 3, "line_end": 3, "side": "worktree", "quote": "const state = \"after\"\n"}})
		}
		answers = append(answers, map[string]any{"requirement_id": []string{"A", "B", "C", "D"}[i], "verdict": verdict, "rationale": rationale, "evidence": evidence, "examined_scope": "Selected review.go only.", "limitations": []string{"No runtime execution."}, "reason": reason})
	}
	const findingTitle = "Next decrements its input"
	const findingQuote = "// Next returns the following integer.\nfunc Next(value int) int { return value - 1 }\n"
	finding := map[string]any{"severity": "low", "title": findingTitle, "description": "Next promises the following integer but subtracts one, returning the preceding integer.", "evidence": []any{map[string]any{"current": map[string]any{"path": "review.go", "line_start": 5, "line_end": 6, "side": "worktree", "quote": findingQuote}}}, "recommendation": "Return value + 1 to match the function contract.", "confidence": "high"}
	wire, _ := json.Marshal(map[string]any{"schema_version": "mulgae-provider-review-output.v3", "summary": "One ordinary finding and independent requirements assessments.", "completeness": "complete", "limitations": []any{}, "findings": []any{finding}, "requirements": map[string]any{"schema_version": "mulgae-provider-requirements.v1", "assessments": answers}})
	body := "# Primary role report\n\nPreserve this accepted report.\n\n```json\n" + string(wire) + "\n```\n"
	providers := canonicalTestTempDir(t)
	providerLog := filepath.Join(canonicalTestTempDir(t), "provider.jsonl")
	bundle, node, launcher := fakeZCodeAppPaths(providers)
	buildFakeZCodeWithReport(t, source, node, launcher, providerLog, "success", "", body)
	environment := isolatedMulgaeEnvWith(t, integrationNativeHome(t, binary), providers)
	initializeOfflineProvidersForRoles(t, binary, project, environment, "zcode", "logic", bundle)
	cli := func(want int, args ...string) map[string]any {
		t.Helper()
		result := runMulgaeBinaryWithEnv(t, binary, project, environment, append(args, "--output", "json")...)
		if result.exitCode != want {
			t.Fatalf("CLI %v exit=%d stdout=%s stderr=%s", args, result.exitCode, result.stdout, result.stderr)
		}
		var envelope map[string]any
		if err := json.Unmarshal(result.stdout, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope["schema_version"] != "mulgae-command-result.v26" {
			t.Fatal("obsolete public envelope")
		}
		return envelope["result"].(map[string]any)
	}
	preflight := cli(0, "review", "--workspace", "--roles", "logic", "--requirements", "requirements.json", "--preflight")["preflight"].(map[string]any)
	if preflight["schema_version"] != "mulgae-review-preflight.v13" || preflight["requirements"].(map[string]any)["execution_available"] != true {
		t.Fatal("Git requirements execution not advertised")
	}
	binding := preflight["project_binding"].(string)
	beforeRejected := contextFixtureFiles(t, filepath.Join(project, ".mulgae"))
	baselineLog, baselineErr := os.ReadFile(providerLog)
	if baselineErr != nil && !os.IsNotExist(baselineErr) {
		t.Fatal(baselineErr)
	}
	if err := os.WriteFile(inputPath, bytes.Replace(input, []byte(`"owner_role":"logic"`), []byte(`"owner_role":"security"`), 1), 0644); err != nil {
		t.Fatal(err)
	}
	cli(2, "review", "--stage", "--roles", "logic", "--requirements", "requirements.json")
	if !reflect.DeepEqual(beforeRejected, contextFixtureFiles(t, filepath.Join(project, ".mulgae"))) {
		t.Fatal("rejected requirements execution allocated private state")
	}
	if err := os.WriteFile(inputPath, input, 0644); err != nil {
		t.Fatal(err)
	}
	noChangeCLI := cli(0, "review", "--stage", "--roles", "logic", "--requirements", "requirements.json", "--expected-project-binding", binding)
	noChangeRun := noChangeCLI["run_id"].(string)
	noChangePage := cli(0, "inspect", "--run", noChangeRun)
	noChangeRequirements := noChangePage["requirements"].(map[string]any)
	if noChangeRequirements["availability"] != "not_run" || noChangeRequirements["selected_count"] != float64(5) || noChangeRequirements["evaluated_count"] != float64(0) || len(noChangePage["role_reports"].([]any)) != 0 {
		t.Fatal("restarted CLI no-change inspection fabricated evaluation/report work")
	}
	for _, item := range noChangeRequirements["items"].([]any) {
		row := item.(map[string]any)
		if row["origin"] != "mulgae_derived" || row["verdict"] != "unverified" || row["reason"] != "no_change_target" {
			t.Fatal("no-change row became a provider claim")
		}
	}
	cli(0, "read-report", "--run", noChangeRun, "--requirement", "A")
	afterNoChange, logErr := os.ReadFile(providerLog)
	if logErr != nil && !os.IsNotExist(logErr) {
		t.Fatal(logErr)
	}
	if !bytes.Equal(baselineLog, afterNoChange) {
		t.Fatal("invalid/no-change execution or restarted reads invoked provider")
	}
	review := cli(0, "review", "--workspace", "--roles", "logic", "--requirements", "requirements.json", "--expected-project-binding", binding)
	run := review["run_id"].(string)
	unfiltered := cli(0, "inspect", "--run", run, "--severity", "low")
	if unfiltered["finding_count"] != float64(1) || len(unfiltered["findings"].([]any)) != 1 {
		t.Fatal("integrated requirements fixture did not admit an ordinary finding")
	}
	unfilteredFinding := unfiltered["findings"].([]any)[0].(map[string]any)
	if unfilteredFinding["title"] != findingTitle || unfilteredFinding["severity"] != "low" {
		t.Fatal("ordinary finding changed during normalization")
	}
	if unfiltered["content_verdict"] != "findings_present" || unfiltered["coverage_status"] != "complete" || unfiltered["structured_extraction_status"] != "structured" || unfiltered["publication_state"] != "committed" || unfiltered["publication_authority"] != "P2" || unfiltered["ci_decision"] != "pass" || len(unfiltered["role_reports"].([]any)) != 1 {
		t.Fatal("assessment verdicts changed independent finding/report/coverage/extraction/publication/CI axes")
	}
	beforeLog, err := os.ReadFile(providerLog)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(project, "review.go")); err != nil {
		t.Fatal(err)
	}
	beforeFiles := contextFixtureFiles(t, project)
	page := cli(0, "inspect", "--run", run, "--requirements-limit", "2", "--severity", "blocker")
	req := page["requirements"].(map[string]any)
	receipt := page["publication_receipt"].(string)
	if receipt != unfiltered["publication_receipt"] {
		t.Fatal("finding severity changed publication identity")
	}
	findingID := unfilteredFinding["id"].(string)
	detail := cli(0, "read-finding", "--run", run, "--finding", findingID, "--expected-project-binding", binding, "--expected-publication-receipt", receipt)
	excerpt := cli(0, "excerpt", "--run", run, "--finding", findingID, "--source-identity-sha256", unfiltered["source_identity_sha256"].(string), "--evidence-index", "0", "--expected-project-binding", binding, "--expected-publication-receipt", receipt)
	if detail["next_offset"] != nil || detail["publication_receipt"] != receipt || !strings.Contains(detail["content"].(string), findingTitle) || excerpt["content"] != findingQuote || excerpt["publication_receipt"] != receipt {
		t.Fatal("ordinary finding detail/evidence lost retained source or receipt")
	}
	primaryReport := cli(0, "read-report", "--run", run, "--role", "logic", "--expected-project-binding", binding, "--expected-publication-receipt", receipt)
	if !strings.HasPrefix(primaryReport["content"].(string), "# Primary role report\n\nPreserve this accepted report.") || primaryReport["publication_receipt"] != receipt {
		t.Fatal("accepted primary report prefix was replaced by normalized assessment output")
	}
	inputSum := sha256.Sum256(input)
	if req["input_sha256"] != "sha256:"+hex.EncodeToString(inputSum[:]) {
		t.Fatal("public input provenance lost exact bytes")
	}
	if req["selected_count"] != float64(5) || req["evaluated_count"] != float64(4) || req["availability"] != "evaluated" || page["finding_count"] != float64(0) {
		t.Fatalf("global independent counts: selected=%v evaluated=%v availability=%v", req["selected_count"], req["evaluated_count"], req["availability"])
	}
	all := []any{}
	links := map[string]string{}
	for {
		req = page["requirements"].(map[string]any)
		all = append(all, req["items"].([]any)...)
		for id, uri := range page["requirement_content_uris"].(map[string]any) {
			links[id] = uri.(string)
		}
		if req["next_cursor"] == nil {
			break
		}
		page = cli(0, "findings", "--run", run, "--requirements-limit", "2", "--requirements-cursor", req["next_cursor"].(string), "--severity", "blocker", "--expected-publication-receipt", receipt)
	}
	if len(all) != 5 {
		t.Fatal("selected requirement omitted by public pagination")
	}
	for i, id := range []string{"A", "B", "C", "D", "E"} {
		row := all[i].(map[string]any)
		if row["requirement_id"] != id {
			t.Fatal("input order changed")
		}
		if row["verdict"] != []string{"met", "unmet", "partially_met", "unverified", "unverified"}[i] {
			t.Fatal("public assessment verdict changed")
		}
		if i == 3 && row["reason"] != "insufficient_evidence" {
			t.Fatal("provider unverified reason changed")
		}

		if i < 4 && row["origin"] != "provider" {
			t.Fatal("valid provider answer became derived")
		}
		if i == 4 && (row["origin"] != "mulgae_derived" || row["reason"] != "answer_omitted") {
			t.Fatal("missing answer not explicit")
		}
	}
	read := func(id string) []byte {
		t.Helper()
		base := []string{"read-report", "--run", run}
		if id != "" {
			base = append(base, "--requirement", id)
		}
		args := append(append([]string{}, base...), "--expected-project-binding", binding, "--expected-publication-receipt", receipt)
		var raw []byte
		for {
			chunk := cli(0, args...)
			part := []byte(chunk["content"].(string))
			if len(part) > 16384 || id != "" && chunk["requirement_id"] != id || chunk["offset"] != float64(len(raw)) {
				t.Fatal("requirement chunk boundary drift")
			}
			raw = append(raw, part...)
			if chunk["next_offset"] == nil {
				sum := sha256.Sum256(raw)
				if chunk["content_sha256"] != "sha256:"+hex.EncodeToString(sum[:]) {
					t.Fatal("content digest drift")
				}
				return raw
			}
			args = append(append([]string{}, base...), "--offset", strconv.Itoa(int(chunk["next_offset"].(float64))), "--expected-project-binding", binding, "--expected-publication-receipt", receipt, "--expected-content-sha256", chunk["content_sha256"].(string))
		}
	}
	contents := map[string][]byte{}
	for _, id := range []string{"A", "B", "C", "D", "E"} {
		contents[id] = read(id)
		var content map[string]any
		if err := json.Unmarshal(contents[id], &content); err != nil || content["requirement_id"] != id {
			t.Fatal("invalid inspected content")
		}
		if id != "E" && content["rationale"] != rationale {
			t.Fatal("rationale truncated")
		}
	}
	rendered := read("")
	if !bytes.Contains(rendered, []byte("B — unmet")) || !bytes.Contains(rendered, []byte("D — unverified")) || !bytes.Contains(rendered, []byte("answer_omitted")) {
		t.Fatal("rendered assessment missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
	number := 0
	call := func(method string, params any) map[string]any {
		t.Helper()
		number++
		raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": number, "method": method, "params": params})
		if _, err := fmt.Fprintln(stdin, string(raw)); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		var response map[string]any
		if err := json.Unmarshal(line, &response); err != nil || response["error"] != nil {
			t.Fatalf("MCP error: %s %v", line, err)
		}
		return response["result"].(map[string]any)
	}
	call("initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "requirements-consumer", "version": "1"}})
	if _, err := fmt.Fprintln(stdin, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); err != nil {
		t.Fatal(err)
	}
	cliPage := cli(0, "inspect", "--run", run, "--requirements-limit", "2", "--severity", "blocker", "--expected-publication-receipt", receipt)
	unfilteredTool := call("tools/call", map[string]any{"name": "inspect_review", "arguments": map[string]any{"run_id": run, "minimum_severity": "low", "requirements_limit": 2, "expected_project_binding": binding, "expected_publication_receipt": receipt}})["structuredContent"].(map[string]any)
	unfilteredData := unfilteredTool["data"].(map[string]any)
	if unfilteredTool["outcome"] != "success" || unfilteredData["finding_count"] != float64(1) || !reflect.DeepEqual(unfilteredData["requirements"], cliPage["requirements"]) {
		t.Fatal("ordinary finding or severity-independent requirements missing from MCP")
	}
	for _, item := range []struct{ uri, content string }{
		{unfilteredFinding["detail_uri"].(string), detail["content"].(string)},
		{unfilteredFinding["evidence"].([]any)[0].(map[string]any)["uri"].(string), findingQuote},
	} {
		resource := call("resources/read", map[string]any{"uri": item.uri})["contents"].([]any)[0].(map[string]any)
		meta := resource["_meta"].(map[string]any)
		if resource["text"] != item.content || meta["publication_receipt"] != receipt || meta["io.mulgae/nextURI"] != nil {
			t.Fatal("CLI/MCP ordinary finding content differs")
		}
	}
	toolCursor := ""
	for index, name := range []string{"inspect_review", "list_findings", "inspect_review"} {
		arguments := map[string]any{"run_id": run, "minimum_severity": "blocker", "requirements_limit": 2, "expected_project_binding": binding, "expected_publication_receipt": receipt}
		if toolCursor != "" {
			arguments["requirements_cursor"] = toolCursor
		}
		response := call("tools/call", map[string]any{"name": name, "arguments": arguments})
		structured := response["structuredContent"].(map[string]any)
		if response["isError"] == true || structured["outcome"] != "success" {
			t.Fatalf("MCP inspection tool failed: %#v", structured)
		}
		data := structured["data"].(map[string]any)
		if data["finding_count"] != float64(0) || data["publication_receipt"] != receipt || !reflect.DeepEqual(data["requirements"], cliPage["requirements"]) || !reflect.DeepEqual(data["requirement_content_uris"], cliPage["requirement_content_uris"]) {
			t.Fatalf("MCP/CLI requirements page %d differs", index)
		}
		next := data["requirements"].(map[string]any)["next_cursor"]
		if index == 2 {
			if next != nil {
				t.Fatal("unexpected fourth assessment page")
			}
			break
		}
		toolCursor = next.(string)
		cliPage = cli(0, "findings", "--run", run, "--requirements-limit", "2", "--requirements-cursor", toolCursor, "--severity", "blocker", "--expected-publication-receipt", receipt)
	}
	for _, id := range []string{"A", "B", "C", "D", "E"} {
		uri := links[id]
		var raw []byte
		for {
			resource := call("resources/read", map[string]any{"uri": uri})["contents"].([]any)[0].(map[string]any)
			meta := resource["_meta"].(map[string]any)
			part := []byte(resource["text"].(string))
			if meta["publication_receipt"] != receipt || meta["requirement_id"] != id || len(part) > 16384 {
				t.Fatal("MCP assessment identity drift")
			}
			raw = append(raw, part...)
			if meta["io.mulgae/nextURI"] == nil {
				break
			}
			uri = meta["io.mulgae/nextURI"].(string)
		}
		if !bytes.Equal(raw, contents[id]) {
			t.Fatal("CLI/MCP requirement bytes differ")
		}
	}
	afterLog, err := os.ReadFile(providerLog)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeLog, afterLog) || !reflect.DeepEqual(beforeFiles, contextFixtureFiles(t, project)) {
		t.Fatal("inspection invoked providers or changed private artifacts")
	}
	// Exercise requirements through the existing asynchronous MCP lifecycle.
	// This explicit empty-stage request must publish without qualification.
	startResult := call("tools/call", map[string]any{"name": "start_review", "arguments": map[string]any{"target": map[string]any{"kind": "stage"}, "roles": []string{"logic"}, "requirements_path": "requirements.json", "expected_project_binding": binding}})
	started := startResult["structuredContent"].(map[string]any)
	if startResult["isError"] == true || started["outcome"] != "success" {
		t.Fatal("MCP requirements start rejected")
	}
	invocation := started["data"].(map[string]any)["invocation_id"].(string)
	awaitResult := call("tools/call", map[string]any{"name": "await_review", "arguments": map[string]any{"invocation_id": invocation}})
	terminal := awaitResult["structuredContent"].(map[string]any)
	if awaitResult["isError"] == true || terminal["outcome"] != "success" {
		t.Fatal("MCP requirements await failed")
	}
	mcpNoChangeRun := terminal["data"].(map[string]any)["run_id"].(string)
	noChangeFiles := contextFixtureFiles(t, project)
	inspected := call("tools/call", map[string]any{"name": "inspect_review", "arguments": map[string]any{"run_id": mcpNoChangeRun, "expected_project_binding": binding}})["structuredContent"].(map[string]any)
	if inspected["outcome"] != "success" {
		t.Fatal("MCP no-change inspection failed")
	}
	mcpNoChange := inspected["data"].(map[string]any)
	mcpRequirements := mcpNoChange["requirements"].(map[string]any)
	if mcpRequirements["availability"] != "not_run" || mcpRequirements["selected_count"] != float64(5) || mcpRequirements["evaluated_count"] != float64(0) || !reflect.DeepEqual(mcpRequirements["items"], noChangeRequirements["items"]) {
		t.Fatal("CLI/MCP no-change assessment semantics differ")
	}
	uri := mcpNoChange["requirement_content_uris"].(map[string]any)["A"].(string)
	content := call("resources/read", map[string]any{"uri": uri})["contents"].([]any)[0].(map[string]any)
	if content["_meta"].(map[string]any)["publication_receipt"] != mcpNoChange["publication_receipt"] {
		t.Fatal("MCP no-change content lost its own receipt")
	}
	afterNoChange, err = os.ReadFile(providerLog)
	if err != nil || !bytes.Equal(beforeLog, afterNoChange) || !reflect.DeepEqual(noChangeFiles, contextFixtureFiles(t, project)) {
		t.Fatal("MCP no-change execution/read invoked provider or read wrote artifacts")
	}
	cli(0, "report", "--run", run, "--output-path", "requirements-report.md")
	writtenReport, err := os.ReadFile(filepath.Join(project, "requirements-report.md"))
	if err != nil || !bytes.Equal(writtenReport, rendered) {
		t.Fatal("legacy file export differs from verified rendered report")
	}
	if err := os.Remove(filepath.Join(project, "requirements-report.md")); err != nil {
		t.Fatal(err)
	}
	// Portable export has no contract for invocation requirements or their
	// private content. Inspect the emitted archive, not runtime private files.
	cli(0, "export", "--run", run, "--output-path", "portable.zip")
	archive, err := zip.OpenReader(filepath.Join(project, "portable.zip"))
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range archive.File {
		if strings.Contains(member.Name, "requirements") {
			t.Fatalf("private requirements member exported: %s", member.Name)
		}
		stream, err := member.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(stream)
		closeErr := stream.Close()
		if readErr != nil || closeErr != nil {
			t.Fatal("export member read failed")
		}
		if bytes.Contains(data, []byte("PRIVATE_INVOCATION_")) || bytes.Contains(data, []byte("Retained rationale")) {
			t.Fatal("private requirement prose entered portable export")
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"portable.zip", "portable.manifest.json"} {
		if err := os.Remove(filepath.Join(project, name)); err != nil {
			t.Fatal(err)
		}
	}
	cli(0, "clean", "--all")
	afterClean := runMulgaeBinaryWithEnv(t, binary, project, environment, "inspect", "--run", run, "--output", "json")
	if afterClean.exitCode == 0 {
		t.Fatal("cleanup left a publicly readable deleted run")
	}
	runDirectory := filepath.Dir(filepath.Join(project, filepath.FromSlash(review["review_artifact_uri"].(string))))
	if _, err := os.Lstat(runDirectory); !os.IsNotExist(err) {
		t.Fatalf("cleanup retained run-owned requirements copies: %v", err)
	}
	retainedInput, err := os.ReadFile(inputPath)
	if err != nil || !bytes.Equal(retainedInput, input) {
		t.Fatal("original invocation input changed")
	}
}
