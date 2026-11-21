//go:build darwin && arm64 && live_e2e && live_grok

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
)

func TestE2EGrokReleaseBinaryReview(t *testing.T) {
	scenario := beginLiveE2ELogScope(t, "scenario", "name=grok-release-binary-review")
	defer scenario.end()

	binary := requireLiveExecutable(t, "MULGAE_E2E_BINARY", "")
	grok := requireLiveExecutable(t, "MULGAE_E2E_GROK_EXECUTABLE", lookupLiveExecutable(t, "grok"))
	validator := newLiveE2EValidator(t)
	environment := liveE2EEnvironment{binary: binary}
	installed, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	herdrRoot := filepath.Join("/private/tmp", fmt.Sprintf("mgh-%d", os.Geteuid()))
	auth := filepath.Join(installed.HomeDir, ".grok", "auth.json")
	authBefore, executableBefore := grokFileDigest(t, auth), grokFileDigest(t, grok)
	operatorBefore := snapshotOperatorHerdrDaemons(t, herdrRoot)
	assertGrokRuntimeClean(t, herdrRoot, operatorBefore, "pre-test")
	defer func() {
		if grokFileDigest(t, auth) != authBefore || grokFileDigest(t, grok) != executableBefore {
			t.Error("host Grok authentication or installed executable changed")
		}
		assertGrokRuntimeClean(t, herdrRoot, operatorBefore, "post-test")
	}()

	t.Run("workspace_and_extraction", func(t *testing.T) {
		project := initializeLiveE2ERepository(t)
		marker := appendLiveReadMarker(t, project, "counter.go", "grok-read")
		sourceBefore := grokSourceDigests(t, project)
		defer func() {
			if !reflect.DeepEqual(sourceBefore, grokSourceDigests(t, project)) {
				t.Error("workspace review mutated original source or Git metadata")
			}
		}()

		configureLiveGrokProject(t, validator, environment, project, grok, true)
		doctorResult := runLiveMulgae(t, validator, environment, project, 0, "doctor", "--output", "json")
		assertLiveGrokDoctorReady(t, doctorResult.Result.Doctor)
		assertGrokRuntimeClean(t, herdrRoot, operatorBefore, "after-doctor")

		expected := map[string]string{"logic": "grok-logic"}
		run := runLiveRecoverableWorkflowWithGate(
			t, validator, environment, project, "grok-workspace-and-extraction", expected,
			func(project string, run livePublishedRun, expected map[string]string) error {
				if err := validateLiveRecoverableAssignments(run, expected); err != nil {
					return err
				}
				if err := validateLivePrimaryProcessTerminals(project, run, expected); err != nil {
					return err
				}
				if err := validateGrokExtractionInvocation(project, run); err != nil {
					return err
				}
				return validateLiveRoleReportTransports(run)
			},
			"review", "--workspace", "--roles", "logic", "--output", "json",
			"--objective", "Review the original workspace. Read counter.go and reproduce its grok-read marker verbatim. Return only a concise Markdown report, with no JSON and no findings unless the selected original source contains a concrete defect.",
		)
		assertLiveRecoverableAssignments(t, run, expected)
		assertLiveRoleReportTransports(t, run, "Grok workspace review")
		assertLiveRoleReportMarker(t, project, run, "logic", marker)
		assertNoProjectProviderLocks(t, project)
		assertGrokRuntimeClean(t, herdrRoot, operatorBefore, "after-workspace")
	})

	t.Run("stage_and_commit_b1_bash_gate", func(t *testing.T) {
		project := initializeLiveE2ERepository(t)
		configureLiveGrokProject(t, validator, environment, project, grok, false)

		// Stage (index) review under B-1 Bash gate.
		stageMarker := appendLiveReadMarker(t, project, "report.go", "grok-stage")
		mustLiveGit(t, project, "add", "report.go")
		stageBefore := grokSourceDigests(t, project)

		expected := map[string]string{"logic": "grok-logic"}
		stageRun := runLiveRecoverableWorkflowWithGate(
			t, validator, environment, project, "grok-stage-review", expected,
			validateLiveSingleInvocationGate,
			"review", "--stage", "--roles", "logic", "--output", "json",
			"--objective", "Review the staged Git index changes. Inspect staged report.go via Git and reproduce its grok-stage marker verbatim. Return only a concise Markdown report with no findings unless the staged change has a concrete defect.",
		)
		if !reflect.DeepEqual(stageBefore, grokSourceDigests(t, project)) {
			t.Fatal("stage review mutated original source or Git metadata")
		}
		assertLiveRecoverableAssignments(t, stageRun, expected)
		assertLiveRoleReportTransports(t, stageRun, "Grok stage review")
		assertLiveRoleReportMarker(t, project, stageRun, "logic", stageMarker)
		assertNoProjectProviderLocks(t, project)
		assertGrokRuntimeClean(t, herdrRoot, operatorBefore, "after-stage")

		// Commit review under B-1 Bash gate.
		commitMarker := appendLiveReadMarker(t, project, "README.md", "grok-commit")
		mustLiveGit(t, project, "add", "README.md")
		mustLiveGit(t, project, "commit", "-m", "Add Grok commit review fixture marker")
		commitSHA := grokGitHeadSHA(t, project)
		commitBefore := grokSourceDigests(t, project)

		commitRun := runLiveRecoverableWorkflowWithGate(
			t, validator, environment, project, "grok-commit-review", expected,
			validateLiveSingleInvocationGate,
			"review", "--commit", commitSHA, "--roles", "logic", "--output", "json",
			"--objective", "Review the selected Git commit. Inspect README.md in that commit and reproduce its grok-commit marker verbatim. Return only a concise Markdown report with no findings unless the commit has a concrete defect.",
		)
		if !reflect.DeepEqual(commitBefore, grokSourceDigests(t, project)) {
			t.Fatal("commit review mutated original source or Git metadata")
		}
		assertLiveRecoverableAssignments(t, commitRun, expected)
		assertLiveRoleReportTransports(t, commitRun, "Grok commit review")
		assertLiveRoleReportMarker(t, project, commitRun, "logic", commitMarker)
		assertNoProjectProviderLocks(t, project)
		assertGrokRuntimeClean(t, herdrRoot, operatorBefore, "after-commit")
	})

	t.Run("retained_error_stops_herdr_immediately", func(t *testing.T) {
		project := initializeLiveE2ERepository(t)
		configureLiveGrokProject(t, validator, environment, project, grok, false)
		sourceBefore := grokSourceDigests(t, project)
		defer func() {
			if !reflect.DeepEqual(sourceBefore, grokSourceDigests(t, project)) {
				t.Error("interrupted review mutated original source or Git metadata")
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, environment.binary,
			"review", "--workspace", "--roles", "logic", "--output", "json",
			"--objective", "Review the workspace thoroughly and carefully analyze every function before responding.",
		)
		cmd.Dir = project
		cmd.Env = os.Environ()
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			t.Fatalf("start interrupted Grok review: %v", err)
		}

		// Wait until the isolated herdr-core session directory appears under
		// /private/tmp/mgh-<uid>, proving herdr-core actually launched before
		// inducing a mid-flight cancellation / retained-diagnostics termination.
		observedSession := false
		startDeadline := time.Now().Add(45 * time.Second)
		for time.Now().Before(startDeadline) {
			if entries, readErr := os.ReadDir(herdrRoot); readErr == nil && len(entries) > 0 {
				observedSession = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !observedSession {
			_ = cmd.Process.Signal(syscall.SIGINT)
			_ = cmd.Wait()
			t.Fatalf("did not observe isolated herdr-core session under %s before interrupt; stdout=%s stderr=%s", herdrRoot, stdout.String(), stderr.String())
		}

		if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
			t.Fatalf("signal mulgae review with SIGINT: %v", err)
		}
		waitErr := cmd.Wait()
		if waitErr == nil {
			t.Fatalf("interrupted Grok review unexpectedly exited 0; stdout=%s", stdout.String())
		}
		assertNoProjectProviderLocks(t, project)
		assertGrokRuntimeClean(t, herdrRoot, operatorBefore, "after-retained-interrupt")
	})

	t.Run("mcp_mode_stops_herdr_while_alive", func(t *testing.T) {
		project := initializeLiveE2ERepository(t)
		marker := appendLiveReadMarker(t, project, "counter.go", "grok-mcp")
		configureLiveGrokProject(t, validator, environment, project, grok, false)
		sourceBefore := grokSourceDigests(t, project)
		defer func() {
			if !reflect.DeepEqual(sourceBefore, grokSourceDigests(t, project)) {
				t.Error("MCP Grok review mutated original source or Git metadata")
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		client := startGrokLiveMCPClient(t, ctx, environment.binary, project)

		structured, callErr := client.callTool("run_review", map[string]any{
			"target":    map[string]any{"kind": "workspace"},
			"roles":     []string{"logic"},
			"objective": "Review the original workspace. Read counter.go and reproduce its grok-mcp marker verbatim. Return only a concise Markdown report with no findings unless the source contains a concrete defect.",
		})
		if callErr != nil {
			t.Fatalf("MCP run_review with Grok failed: %v", callErr)
		}
		schemaVersion, _ := structured["schema_version"].(string)
		outcome, _ := structured["outcome"].(string)
		if schemaVersion != "mulgae-mcp-tool-result.v1" ||
			(outcome != "success" && outcome != "request_changes") ||
			structured["error"] != nil {
			t.Fatalf("MCP run_review returned unexpected structured result: %#v", structured)
		}
		// While mulgae mcp is STILL ALIVE, assert zero Mulgae herdr-core/holder/
		// watchdog/grok processes remain and /private/tmp/mgh-<uid> is empty!
		if err := client.cmd.Process.Signal(syscall.Signal(0)); err != nil {
			t.Fatalf("MCP server exited prematurely before post-review check: %v", err)
		}
		if _, err := client.rpc("tools/list", map[string]any{}); err != nil {
			t.Fatalf("MCP server unresponsive after Grok review: %v", err)
		}
		assertGrokRuntimeClean(t, herdrRoot, operatorBefore, "while-mcp-alive")

		// Verify marker was captured in the published role report.
		dataMap, ok := structured["data"].(map[string]any)
		if !ok {
			t.Fatalf("MCP run_review missing structured data map: %#v", structured)
		}
		sessionID, _ := dataMap["session_id"].(string)
		runID, _ := dataMap["run_id"].(string)
		if sessionID == "" || runID == "" {
			t.Fatalf("MCP run_review missing session_id or run_id in structured data: %#v", dataMap)
		}
		assertGrokMCPRoleReportMarker(t, project, sessionID, runID, "logic", marker)

		// Close stdin cleanly and confirm clean MCP exit + zero leaked processes.
		if err := client.closeAndWait(); err != nil {
			t.Fatalf("MCP server clean shutdown failed: %v", err)
		}
		assertNoProjectProviderLocks(t, project)
		assertGrokRuntimeClean(t, herdrRoot, operatorBefore, "after-mcp-exit")
	})

	scenario.status = "passed"
}

func configureLiveGrokProject(
	t *testing.T,
	validator *jsonschema.Validator,
	environment liveE2EEnvironment,
	project, grok string,
	extraction bool,
) {
	t.Helper()
	initialized := runLiveMulgae(t, validator, environment, project, 0,
		"init", "--providers", "grok", "--roles", "logic",
		"--grok-executable", grok, "--output", "json",
	)
	if initialized.Result.Kind != "initialized" {
		t.Fatalf("Grok init result kind = %q", initialized.Result.Kind)
	}
	config := readE2EConfig(t, project)
	config.Validation.Repair = adapterconfig.RepairConfig{}
	config.Validation.Extraction.Enabled = extraction
	config.Validation.Extraction.EnabledExplicit = true
	config.Resources.PrimaryRepairAttempts = 0
	// PreflightRunBudgetWithCapacity models 2 structural invocation slots per
	// role even without repair/extraction; single-invocation behavior is
	// enforced by validateLiveSingleInvocationGate.
	config.Resources.RoleMaxInvocations = 2
	config.Resources.RunMaxInvocations = 2
	projectConfig, localConfig, err := adapterconfig.EncodeSplit(config)
	if err != nil {
		t.Fatal(err)
	}
	writeLiveExistingConfig(t, filepath.Join(project, ".mulgae", "config.yaml"), projectConfig)
	writeLiveExistingConfig(t, filepath.Join(project, ".mulgae", "local.yaml"), localConfig)
}

func assertLiveGrokDoctorReady(t *testing.T, raw json.RawMessage) {
	t.Helper()
	var doctor struct {
		ConfiguredProviderIDs []string `json:"configured_provider_ids"`
		Readiness             struct {
			State string `json:"state"`
		} `json:"readiness"`
		ProviderInventory []struct {
			Family string `json:"family"`
			State  string `json:"state"`
			Reason string `json:"reason"`
		} `json:"provider_inventory"`
	}
	if err := json.Unmarshal(raw, &doctor); err != nil {
		t.Fatalf("decode Grok doctor result: %v", err)
	}
	if doctor.Readiness.State != "ready" || !reflect.DeepEqual(doctor.ConfiguredProviderIDs, []string{"grok"}) {
		t.Fatalf("Grok doctor readiness = %#v", doctor)
	}
	for _, row := range doctor.ProviderInventory {
		if row.Family == "grok" && row.State == "eligible" &&
			(row.Reason == "provider_cli_version_supported" || row.Reason == "provider_cli_version_newer_than_verified") {
			return
		}
	}
	t.Fatalf("Grok doctor did not report eligible grok CLI version: %#v", doctor.ProviderInventory)
}

func grokGitHeadSHA(t *testing.T, project string) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = project
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git rev-parse HEAD: %v: %s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func assertGrokMCPRoleReportMarker(t *testing.T, project, sessionID, runID, role, marker string) {
	t.Helper()
	path := filepath.Join(project, ".mulgae", sessionID, runID, "role-reports", role+".md")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read MCP Grok role report %s: %v", path, err)
	}
	if !strings.Contains(string(body), marker) {
		t.Fatalf("MCP Grok role report %s missing marker %q: %s", path, marker, body)
	}
}

type grokLiveMCPClient struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	output *bufio.Reader
	stderr *bytes.Buffer
	id     int
	closed bool
}

func startGrokLiveMCPClient(t *testing.T, ctx context.Context, binary, project string) *grokLiveMCPClient {
	t.Helper()
	cmd := exec.CommandContext(ctx, binary, "mcp", "--project-root", project)
	cmd.Dir = project
	cmd.Env = os.Environ()
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	client := &grokLiveMCPClient{
		cmd:    cmd,
		input:  input,
		output: bufio.NewReader(output),
		stderr: &stderr,
	}
	t.Cleanup(func() {
		if !client.closed {
			_ = client.closeAndWait()
		}
	})
	if _, err := client.rpc("initialize", map[string]any{
		"protocolVersion": "2025-11-25",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "mulgae-grok-e2e", "version": "1"},
	}); err != nil {
		t.Fatalf("MCP initialize failed: %v (stderr=%s)", err, stderr.String())
	}
	if _, err := fmt.Fprintln(input, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); err != nil {
		t.Fatalf("MCP initialized notification failed: %v", err)
	}
	return client
}

func (c *grokLiveMCPClient) rpc(method string, params any) (json.RawMessage, error) {
	c.id++
	raw, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      c.id,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintln(c.input, string(raw)); err != nil {
		return nil, err
	}
	for {
		line, err := c.output.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("read MCP response for %s: %w (stderr=%s)", method, err, c.stderr.String())
		}
		var envelope struct {
			ID     *int            `json:"id"`
			Method string          `json:"method"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(line, &envelope); err != nil {
			return nil, fmt.Errorf("decode MCP line %q: %w", string(line), err)
		}
		// Ignore server-initiated notifications (e.g., progress updates).
		if envelope.ID == nil {
			continue
		}
		if *envelope.ID != c.id {
			return nil, fmt.Errorf("unexpected MCP response id %d (want %d): %s", *envelope.ID, c.id, line)
		}
		if len(envelope.Error) != 0 {
			return nil, fmt.Errorf("MCP error for %s: %s", method, envelope.Error)
		}
		return envelope.Result, nil
	}
}

func (c *grokLiveMCPClient) callTool(name string, arguments any) (map[string]any, error) {
	raw, err := c.rpc("tools/call", map[string]any{"name": name, "arguments": arguments})
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

func (c *grokLiveMCPClient) closeAndWait() error {
	c.closed = true
	_ = c.input.Close()
	if err := c.cmd.Wait(); err != nil {
		return fmt.Errorf("%w (stderr=%s)", err, c.stderr.String())
	}
	return nil
}

type operatorHerdrDaemon struct {
	pid    int
	lstart string
	cmd    string
}

func runPSCommand(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("/bin/ps", args...)
	cmd.Env = []string{"LC_ALL=C", "PATH=/bin:/usr/bin"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("/bin/ps %v failed: %v (%s)", args, err, out)
	}
	return string(out)
}

// snapshotOperatorHerdrDaemons records any pre-existing non-Mulgae herdr-core
// daemon/holder processes using /bin/ps only (never contacting hc ls/status).
func snapshotOperatorHerdrDaemons(t *testing.T, herdrRoot string) map[int]operatorHerdrDaemon {
	t.Helper()
	out := runPSCommand(t, "-axww", "-o", "pid=,ppid=,lstart=,command=")
	result := make(map[int]operatorHerdrDaemon)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		lstart := strings.Join(fields[2:7], " ")
		command := strings.Join(fields[7:], " ")
		if strings.Contains(command, herdrRoot) {
			continue
		}
		if strings.Contains(command, "--hc-launchd") || strings.Contains(command, "/default/default.holder.") {
			result[pid] = operatorHerdrDaemon{pid: pid, lstart: lstart, cmd: command}
		}
	}
	return result
}

func assertGrokRuntimeClean(t *testing.T, herdrRoot string, operatorBefore map[int]operatorHerdrDaemon, phase string) {
	t.Helper()
	for _, prefix := range []string{"mulgae-review-namespaces-*", "mulgae-review-workspaces-*"} {
		remaining, err := filepath.Glob(filepath.Join(os.TempDir(), prefix))
		if err != nil || len(remaining) != 0 {
			t.Fatalf("[%s] Grok review left private runtime roots behind: %v (err=%v)", phase, remaining, err)
		}
	}
	if entries, err := os.ReadDir(herdrRoot); err == nil && len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("[%s] isolated herdr-core session directories survived under %s: %v", phase, herdrRoot, names)
	}

	// Inspect process table with environment to confirm zero Mulgae-owned
	// herdr-core, holder, watchdog, trampoline, or grok processes leaked.
	selfPID := os.Getpid()
	psEnvOut := runPSCommand(t, "-axww", "-E", "-o", "pid=,ppid=,command=")
	var leaked []string
	for _, line := range strings.Split(psEnvOut, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid == selfPID {
			continue
		}
		rest := strings.Join(fields[2:], " ")
		if strings.Contains(rest, "__mulgae_herdr_watchdog_v1") ||
			strings.Contains(rest, "__mulgae_paneexec_v1") ||
			strings.Contains(rest, herdrRoot+"/") ||
			strings.Contains(rest, "MULGAE_TERMINAL_PROFILE_SENTINEL=") ||
			strings.Contains(rest, "MULGAE_PROVIDER_SCRATCH=") ||
			strings.Contains(rest, "mulgae-review-namespaces-") {
			leaked = append(leaked, fmt.Sprintf("pid=%d %s", pid, truncateGrokPSLine(rest, 240)))
		}
	}
	if len(leaked) != 0 {
		t.Fatalf("[%s] leaked Mulgae herdr-core/holder/watchdog/grok processes:\n%s", phase, strings.Join(leaked, "\n"))
	}

	// Confirm every pre-existing operator herdr-core daemon/holder still exists
	// with the exact same PID and lstart.
	operatorAfter := snapshotOperatorHerdrDaemons(t, herdrRoot)
	for pid, before := range operatorBefore {
		after, ok := operatorAfter[pid]
		if !ok {
			t.Fatalf("[%s] pre-existing operator herdr-core process disappeared: pid=%d lstart=%q cmd=%q", phase, pid, before.lstart, before.cmd)
		}
		if after.lstart != before.lstart {
			t.Fatalf("[%s] pre-existing operator herdr-core process restarted: pid=%d before=%q after=%q", phase, pid, before.lstart, after.lstart)
		}
	}
}

func truncateGrokPSLine(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func validateGrokExtractionInvocation(project string, run livePublishedRun) error {
	attempts := liveAttemptsForRole(run.manifest.Attempts, "logic")
	if len(attempts) != 1 || attempts[0].ProviderInstance != "grok-logic" || attempts[0].InvocationCount != 2 ||
		run.manifest.StructuredExtractionState != "structured" || run.review.StructuredExtractionStatus != "structured" {
		return fmt.Errorf("Grok gate requires one initial review and successful same-provider structured extraction")
	}
	path := filepath.Join(project, ".mulgae", "diagnostics", run.manifest.SessionID, run.manifest.RunID,
		"attempts", attempts[0].AttemptID, "invocations", "002-extract", "status.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read Grok extraction invocation status: %w", err)
	}
	var status liveInvocationStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return fmt.Errorf("decode Grok extraction invocation status: %w", err)
	}
	started, startErr := time.Parse(time.RFC3339Nano, status.StartedAt)
	completed, completeErr := time.Parse(time.RFC3339Nano, status.CompletedAt)
	if startErr != nil || completeErr != nil || status.ProcessState != "succeeded" || !started.Before(completed) {
		return fmt.Errorf("Grok extraction did not complete successfully")
	}
	return nil
}

func grokFileDigest(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func grokSourceDigests(t *testing.T, project string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	err := filepath.WalkDir(project, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == filepath.Join(project, ".mulgae") {
			return filepath.SkipDir
		}
		relative, err := filepath.Rel(project, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			result[relative] = info.Mode().String()
		} else {
			result[relative] = info.Mode().String() + ":" + grokFileDigest(t, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
