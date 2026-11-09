//go:build darwin && arm64 && vm_qualification

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// vmStableCommandFields preserves the entire command outcome except the
// completion timestamp and request identity of each separate read operation.
func vmStableCommandFields(t *testing.T, envelope map[string]any) map[string]any {
	t.Helper()
	completed, ok := envelope["completed_at"].(string)
	if !ok {
		t.Fatal("command envelope omitted completed_at")
	}
	if _, err := time.Parse(time.RFC3339Nano, completed); err != nil {
		t.Fatalf("invalid command completed_at: %v", err)
	}
	request, ok := envelope["request"].(map[string]any)
	if !ok {
		t.Fatal("command envelope omitted request")
	}
	if requestID, ok := request["request_id"].(string); !ok || requestID == "" {
		t.Fatal("command envelope omitted request_id")
	}
	stableRequest := make(map[string]any, len(request)-1)
	for name, value := range request {
		if name != "request_id" {
			stableRequest[name] = value
		}
	}
	stable := make(map[string]any, len(envelope)-1)
	for name, value := range envelope {
		if name != "completed_at" {
			stable[name] = value
		}
	}
	stable["request"] = stableRequest
	return stable
}

// vmRunOwnedTreeMaterial snapshots every existing publication or runtime
// diagnostic artifact tree owned by sessionID/runID without fabricating
// missing directories for no-change or all-roles-failed runs.
func vmRunOwnedTreeMaterial(t *testing.T, project, sessionID, runID string, extraURIs ...string) map[string]string {
	t.Helper()

	candidates := []string{
		filepath.Join(project, ".mulgae", sessionID, runID),
		filepath.Join(project, ".mulgae", "diagnostics", sessionID, runID),
	}
	for _, uri := range extraURIs {
		if uri == "" {
			continue
		}
		candidates = append(candidates, filepath.Join(project, filepath.FromSlash(uri)))
	}

	combined := map[string]string{}
	seenRoots := map[string]bool{}
	for _, candidate := range candidates {
		clean := filepath.Clean(candidate)
		if seenRoots[clean] {
			continue
		}
		info, err := os.Lstat(clean)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatalf("stat owned run path %s: %v", clean, err)
		}
		seenRoots[clean] = true
		relRoot, relErr := filepath.Rel(project, clean)
		if relErr != nil {
			t.Fatal(relErr)
		}
		if !info.IsDir() {
			data, readErr := os.ReadFile(clean)
			if readErr != nil {
				t.Fatal(readErr)
			}
			sum := sha256.Sum256(data)
			combined[filepath.ToSlash(relRoot)] = hex.EncodeToString(sum[:])
			continue
		}
		for name, digest := range snapshotTestTreeMaterial(t, clean) {
			combined[filepath.ToSlash(filepath.Join(relRoot, name))] = digest
		}
	}
	if len(combined) == 0 {
		t.Fatalf("run %s/%s left no owned publication or diagnostic artifacts under %s", sessionID, runID, project)
	}
	return combined
}

// vmNativeZeroCallCompatibility proves that local context, preflight,
// no-change review publication, and receipt-bound CLI + MCP reads make zero
// provider calls and zero Haepari controller calls even when HAEPARI_HOME
// points to an unstarted directory.
func vmNativeZeroCallCompatibility(
	t *testing.T,
	ctx context.Context,
	haepari, binary, work, project, oldID, failedID, committedRunID, logPath string,
	environment []string,
) {
	t.Helper()

	beforeLocks := vmHaepari(t, haepari, work, environment, "locks", "list", "--lock", "mulgae-review", "--json")
	beforeRequestCount := len(beforeLocks["requests"].([]any))
	beforeProviderCount := len(fakeZCodeReviewObservations(t, logPath))

	unstartedHome := filepath.Join(work, "unstarted-haepari-home")
	unstartedEnv := append(withHaepariHome(environment, unstartedHome), "HAEPARI_LOCK_GRANT=")

	contextResult := vmCLI(t, binary, project, unstartedEnv, 0, "context")["result"].(map[string]any)
	binding, ok := contextResult["project_binding"].(string)
	if !ok || binding == "" {
		t.Fatalf("zero-call context omitted project_binding: %#v", contextResult)
	}

	preflight := vmCLI(t, binary, project, unstartedEnv, 0,
		"review", "--head", "--roles", "logic", "--preflight", "--expected-project-binding", binding,
	)["result"].(map[string]any)["preflight"].(map[string]any)
	if preflight["project_binding"] != binding {
		t.Fatalf("zero-call CLI preflight binding = %v, want %s", preflight["project_binding"], binding)
	}

	// Stage is clean in project after the target commit, so --stage exercises
	// the candidate no-change publication path without a controller or provider.
	noChangeRun := vmCLI(t, binary, project, unstartedEnv, 0,
		"review", "--stage", "--roles", "logic", "--requirements", "requirements.json", "--expected-project-binding", binding,
	)["result"].(map[string]any)
	noChangeRunID, ok := noChangeRun["run_id"].(string)
	if !ok || noChangeRunID == "" {
		t.Fatalf("candidate no-change review omitted run_id: %#v", noChangeRun)
	}
	noChangeInspect := vmCLI(t, binary, project, unstartedEnv, 0,
		"inspect", "--run", noChangeRunID, "--expected-project-binding", binding,
	)["result"].(map[string]any)
	noChangeReq := noChangeInspect["requirements"].(map[string]any)
	if noChangeReq["availability"] != "not_run" || noChangeReq["selected_count"] != float64(1) || noChangeReq["evaluated_count"] != float64(0) {
		t.Fatalf("candidate no-change requirements projection = %#v", noChangeReq)
	}

	oldInspect := vmCLI(t, binary, project, unstartedEnv, 0,
		"inspect", "--run", oldID, "--expected-project-binding", binding,
	)["result"].(map[string]any)
	oldReceipt, ok := oldInspect["publication_receipt"].(string)
	if !ok || oldReceipt == "" {
		t.Fatalf("old run inspect omitted publication_receipt: %#v", oldInspect)
	}
	vmCLI(t, binary, project, unstartedEnv, 0,
		"inspect", "--run", oldID, "--expected-project-binding", binding, "--expected-publication-receipt", oldReceipt,
	)
	oldReqReport := vmCLI(t, binary, project, unstartedEnv, 0,
		"read-report", "--run", oldID, "--requirement", "KEEP-1", "--expected-project-binding", binding, "--expected-publication-receipt", oldReceipt,
	)["result"].(map[string]any)

	committedInspect := vmCLI(t, binary, project, unstartedEnv, 0,
		"inspect", "--run", committedRunID, "--expected-project-binding", binding,
	)["result"].(map[string]any)
	committedReceipt, ok := committedInspect["publication_receipt"].(string)
	if !ok || committedReceipt == "" {
		t.Fatalf("committed run inspect omitted publication_receipt: %#v", committedInspect)
	}
	committedRoleReport := vmCLI(t, binary, project, unstartedEnv, 0,
		"read-report", "--run", committedRunID, "--role", "logic", "--expected-project-binding", binding, "--expected-publication-receipt", committedReceipt,
	)["result"].(map[string]any)
	vmCLI(t, binary, project, unstartedEnv, 0, "status", "--run", committedRunID)
	vmCLI(t, binary, project, unstartedEnv, 0, "status", "--run", failedID)

	client := startCoordinationMCP(t, ctx, binary, project, unstartedEnv)
	callTool := func(name string, arguments any) map[string]any {
		t.Helper()
		result, err := client.tool(name, arguments)
		if err != nil || result["outcome"] != "success" {
			t.Fatalf("zero-call MCP %s failed: %+v / %v", name, result, err)
		}
		return result["data"].(map[string]any)
	}

	if callTool("get_context", map[string]any{})["project_binding"] != binding {
		t.Fatal("zero-call MCP get_context binding mismatch")
	}
	if callTool("preflight_review", map[string]any{
		"target":                   map[string]any{"kind": "head"},
		"roles":                    []string{"logic"},
		"expected_project_binding": binding,
	})["project_binding"] != binding {
		t.Fatal("zero-call MCP preflight_review binding mismatch")
	}

	mcpOldPage := callTool("inspect_review", map[string]any{
		"run_id":                       oldID,
		"expected_project_binding":     binding,
		"expected_publication_receipt": oldReceipt,
	})
	if !reflect.DeepEqual(mcpOldPage["requirements"], oldInspect["requirements"]) || mcpOldPage["publication_receipt"] != oldReceipt {
		t.Fatalf("zero-call CLI/MCP old inspect disagreement: %#v vs %#v", mcpOldPage, oldInspect)
	}
	reqURI := mcpOldPage["requirement_content_uris"].(map[string]any)["KEEP-1"].(string)
	rawReqResource, err := client.rpc("resources/read", map[string]any{"uri": reqURI})
	if err != nil {
		t.Fatalf("zero-call MCP resources/read requirement URI: %v", err)
	}
	var reqResource struct {
		Contents []struct {
			Text string         `json:"text"`
			Meta map[string]any `json:"_meta"`
		} `json:"contents"`
	}
	if err := json.Unmarshal(rawReqResource, &reqResource); err != nil || len(reqResource.Contents) != 1 ||
		reqResource.Contents[0].Text != oldReqReport["content"] || reqResource.Contents[0].Meta["publication_receipt"] != oldReceipt {
		t.Fatalf("zero-call MCP requirement resource mismatch: %s / %v", rawReqResource, err)
	}

	mcpCommittedPage := callTool("inspect_review", map[string]any{
		"run_id":                       committedRunID,
		"expected_project_binding":     binding,
		"expected_publication_receipt": committedReceipt,
	})
	roleReports, ok := mcpCommittedPage["role_reports"].([]any)
	if !ok || len(roleReports) == 0 {
		t.Fatalf("zero-call MCP inspect_review omitted role_reports: %#v", mcpCommittedPage)
	}
	roleURI := roleReports[0].(map[string]any)["uri"].(string)
	rawRoleResource, err := client.rpc("resources/read", map[string]any{"uri": roleURI})
	if err != nil {
		t.Fatalf("zero-call MCP resources/read role URI: %v", err)
	}
	var roleResource struct {
		Contents []struct {
			Text string         `json:"text"`
			Meta map[string]any `json:"_meta"`
		} `json:"contents"`
	}
	if err := json.Unmarshal(rawRoleResource, &roleResource); err != nil || len(roleResource.Contents) != 1 ||
		roleResource.Contents[0].Text != committedRoleReport["content"] || roleResource.Contents[0].Meta["publication_receipt"] != committedReceipt {
		t.Fatalf("zero-call MCP role report resource mismatch: %s / %v", rawRoleResource, err)
	}

	callTool("get_run", map[string]any{"run_id": oldID})
	callTool("get_run", map[string]any{"run_id": committedRunID})

	if _, statErr := os.Stat(unstartedHome); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("zero-call operations created or touched unstarted HAEPARI_HOME: %v", statErr)
	}
	afterLocks := vmHaepari(t, haepari, work, environment, "locks", "list", "--lock", "mulgae-review", "--json")
	if got := len(afterLocks["requests"].([]any)); got != beforeRequestCount {
		t.Fatalf("zero-call operations mutated controller lock requests: before=%d after=%d", beforeRequestCount, got)
	}
	if got := len(fakeZCodeReviewObservations(t, logPath)); got != beforeProviderCount {
		t.Fatalf("zero-call operations invoked provider: before=%d after=%d", beforeProviderCount, got)
	}

	vmWriteJSON(t, filepath.Join(work, "compatibility-zero-call-result.json"), map[string]any{
		"schema":                    "mulgae.vm-zero-call-compatibility/v1",
		"project_binding":           binding,
		"old_run_id":                oldID,
		"old_publication_receipt":   oldReceipt,
		"committed_run_id":          committedRunID,
		"committed_receipt":         committedReceipt,
		"candidate_no_change_run":   noChangeRunID,
		"provider_calls_delta":      0,
		"controller_requests_delta": 0,
	})
}
