//go:build darwin && arm64 && vm_qualification

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/herdr"
	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/ports"
)

// TestVMQualificationNative uses a released controller process, not the HTTP
// fixture used by the deterministic fault tests. The outer Job owns VM access.
func TestVMQualificationNative(t *testing.T) {
	if os.Getenv("HAEPARI_PARENT_CONTEXT") == "" {
		t.Fatal("qualification requires the managed guest entrypoint")
	}
	hv, err := exec.Command("/usr/sbin/sysctl", "-n", "kern.hv_vmm_present").Output()
	if err != nil || strings.TrimSpace(string(hv)) != "1" {
		t.Fatal("qualification requires a virtual Darwin guest")
	}
	binary := vmRequiredFile(t, "MULGAE_E2E_BINARY")
	oldBinary := vmRequiredFile(t, "MULGAE_VM_PRIOR_BINARY")
	haepari := vmRequiredFile(t, "MULGAE_VM_HAEPARI_BINARY")
	work := os.Getenv("MULGAE_VM_WORK_ROOT")
	if !filepath.IsAbs(work) {
		t.Fatal("MULGAE_VM_WORK_ROOT must be an owned absolute directory")
	}
	var finalResult map[string]any
	t.Cleanup(func() {
		if finalResult != nil && !t.Failed() {
			vmWriteJSON(t, filepath.Join(work, "native-result.json"), finalResult)
		}
	})
	root := repositoryRoot(t)
	for _, name := range []string{"home", "native", "providers", "project"} {
		if err := os.Mkdir(filepath.Join(work, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	home := filepath.Join(work, "home")
	providers, project := filepath.Join(work, "providers"), filepath.Join(work, "project")
	environment := []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + home, "USER=" + os.Getenv("USER"),
		"TMPDIR=" + os.Getenv("TMPDIR"), "GOCACHE=" + os.Getenv("GOCACHE"),
		"GOMODCACHE=" + os.Getenv("GOMODCACHE"), "GOTOOLCHAIN=local",
		"HAEPARI_PARENT_CONTEXT=" + os.Getenv("HAEPARI_PARENT_CONTEXT"),
	}
	controllerHome := os.Getenv("MULGAE_VM_REVIEW_HOME")
	if !filepath.IsAbs(controllerHome) {
		t.Fatal("missing admitted isolated review controller home")
	}
	if err := os.Mkdir(controllerHome, 0700); err != nil {
		t.Fatal(err)
	}
	controllerIdentity, err := os.Stat(controllerHome)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		current, err := os.Stat(controllerHome)
		if err != nil || !os.SameFile(current, controllerIdentity) {
			t.Error("owned controller root changed; cleanup refused")
			return
		}
		if err := os.RemoveAll(controllerHome); err != nil {
			t.Error(err)
		}
	})
	environment = append(environment, "HAEPARI_HOME="+controllerHome)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	t.Cleanup(cancel)
	controller := vmStartController(t, ctx, haepari, controllerHome, environment)
	defer func() { controller.stop(t) }()
	resource := filepath.Join(work, "review-resource.json")
	mustWriteTestFile(t, resource, []byte(`{"schema":"haepari.resource/v1","id":"mulgae-review","kind":"lock","capacity":1}`))
	vmHaepari(t, haepari, work, environment, "resource", "register", "--file", resource, "--json")
	beforeRestart := vmHaepari(t, haepari, work, environment, "resource", "inspect", "mulgae-review", "--json")
	if _, err := os.Stat(filepath.Join(controllerHome, "state.sqlite")); err != nil {
		t.Fatalf("real controller did not create SQLite state: %v", err)
	}

	bundle, node, launcher := fakeZCodeAppPaths(providers)
	logPath := filepath.Join(work, "provider.jsonl")
	mustWriteTestFile(t, logPath, nil)
	barrier := filepath.Join(work, "barrier")
	if err := os.Mkdir(barrier, 0700); err != nil {
		t.Fatal(err)
	}
	priorBundle, priorNode, priorLauncher := priorZCodeAppPaths(providers)
	buildPriorZCodeWithReport(t, root, priorNode, priorLauncher, filepath.Join(work, "prior-provider.jsonl"), "fail_review", "", fakeZCodeReportTemplate)
	initializeReviewGitRepository(t, project)
	oldEnvironment := environment
	initializeOfflineProvidersForRoles(t, oldBinary, project, oldEnvironment, "zcode", "logic,security", priorBundle)
	priorPolicy := vmConfigureAndCapturePriorPolicy(t, oldBinary, project, oldEnvironment)
	// Both historical states are produced by the old installed CLI. The empty
	// staged selection publishes without a provider; the controlled provider
	// then fails a real workspace review before the upgrade.
	requirements := []byte(`{"schema_version":"mulgae-requirements-input.v1","requirements":[{"id":"KEEP-1","text":"Retain prior results","acceptance_criteria":["Old requirements remain readable"],"owner_role":"logic"}]}`)
	mustWriteTestFile(t, filepath.Join(project, "requirements.json"), requirements)
	oldRun := vmCLI(t, oldBinary, project, oldEnvironment, 0, "review", "--stage", "--roles", "logic", "--requirements", "requirements.json")["result"].(map[string]any)
	oldID := oldRun["run_id"].(string)
	oldSessionID := oldRun["session_id"].(string)
	oldPage := vmCLI(t, oldBinary, project, oldEnvironment, 0, "inspect", "--run", oldID)["result"].(map[string]any)
	oldHistory := vmRunOwnedTreeMaterial(t, project, oldSessionID, oldID)
	failed := runMulgaeBinaryWithEnv(t, oldBinary, project, oldEnvironment, "review", "--workspace", "--roles", "logic", "--output", "json")
	if failed.exitCode == 0 {
		t.Fatal("old failing-provider review unexpectedly succeeded")
	}
	var failedEnvelope commandEnvelope
	if err := json.Unmarshal(failed.stdout, &failedEnvelope); err != nil || failedEnvelope.Result.RunID == nil || failedEnvelope.Result.SessionID == nil {
		t.Fatalf("old failure did not preserve an actual run: %s / %v", failed.stdout, err)
	}
	failedID := *failedEnvelope.Result.RunID
	failedSessionID := *failedEnvelope.Result.SessionID
	var failedArtifactURI string
	if len(failedEnvelope.Reasons) > 0 && failedEnvelope.Reasons[0].ArtifactURI != nil {
		failedArtifactURI = *failedEnvelope.Reasons[0].ArtifactURI
	}
	oldFailed := vmCLI(t, oldBinary, project, oldEnvironment, 0, "status", "--run", failedID)
	failedHistory := vmRunOwnedTreeMaterial(t, project, failedSessionID, failedID, failedArtifactURI)
	buildFakeZCodeWithBarrier(t, root, node, launcher, logPath, barrier)
	environment = vmZCodeToolsEnvironment(environment, node, launcher)
	// Configuration bytes, including the private file mode, are the old CLI's
	// actual output; candidate init is never invoked on the retained project.
	oldConfig := vmConfigMaterial(t, project)
	currentPolicy := vmCLI(t, binary, project, environment, 0, "config", "--mode", "effective")["result"].(map[string]any)
	vmAssertPriorEffectivePolicy(t, currentPolicy)
	if !reflect.DeepEqual(priorPolicy["effective"], currentPolicy) {
		t.Fatal("candidate reclassified the actual old custom policy")
	}
	vmCLI(t, binary, project, environment, 0, "config", "--mode", "provenance")
	upgradedFailed := vmCLI(t, binary, project, environment, 0, "status", "--run", failedID)
	vmWriteJSON(t, filepath.Join(work, "prior-status-result.json"), map[string]any{"old": oldFailed, "candidate": upgradedFailed})
	if !reflect.DeepEqual(vmStableCommandFields(t, oldFailed), vmStableCommandFields(t, upgradedFailed)) {
		t.Fatal("candidate reclassified the actual old failed-recovery status")
	}
	if !reflect.DeepEqual(oldConfig, vmConfigMaterial(t, project)) {
		t.Fatal("candidate changed the old configuration")
	}
	state := map[string]any{
		"schema": "mulgae.vm-native-baseline/v1", "project": project,
		"old_run_id": oldID, "old_requirements": oldPage["requirements"], "old_custom_policy": priorPolicy,
		"old_failed_exit": failed.exitCode, "old_failed_run_id": failedID, "old_failed_status": oldFailed, "configuration": oldConfig,
		"old_coordination_intent": "not_applicable: v0.1.26 predates native coordination",
		"controller_home":         controllerHome, "controller_evidence": "released foreground process and state.sqlite",
	}
	vmWriteJSON(t, filepath.Join(work, "prior-state.json"), state)

	// A real daemon restart must preserve its registered capacity-one resource.
	controller.stop(t)
	controller = vmStartController(t, ctx, haepari, controllerHome, environment)
	afterRestart := vmHaepari(t, haepari, work, environment, "resource", "inspect", "mulgae-review", "--json")
	for _, key := range []string{"resource_id", "kind", "config_revision", "configuration_digest"} {
		if !reflect.DeepEqual(beforeRestart[key], afterRestart[key]) {
			t.Fatalf("resource %s changed across real restart", key)
		}
	}
	if !reflect.DeepEqual(oldConfig, vmConfigMaterial(t, project)) ||
		!reflect.DeepEqual(oldHistory, vmRunOwnedTreeMaterial(t, project, oldSessionID, oldID)) {
		t.Fatal("restart changed retained project material")
	}

	runTestCommand(t, project, "git", "add", "review.go")
	runTestCommand(t, project, "git", "-c", "user.name=Mulgae VM", "-c", "user.email=mulgae-vm@example.invalid", "commit", "-m", "review target")
	waiterProject := filepath.Join(work, "waiter-project")
	if err := os.Mkdir(waiterProject, 0700); err != nil {
		t.Fatal(err)
	}
	initializeReviewGitRepository(t, waiterProject)
	initializeOfflineProvidersForRoles(t, binary, waiterProject, environment, "zcode", "logic,security", bundle)
	var committedRunID string
	// Provider barriers expose overlap across independent projects without mocking the controller.
	for _, route := range []string{"cli", "foreground", "async", "cancel", "cancel_race"} {
		if !t.Run(route, func(t *testing.T) {
			markers, err := filepath.Glob(filepath.Join(barrier, "*.ready"))
			if err != nil {
				t.Fatal(err)
			}
			for _, marker := range markers {
				if err := os.Remove(marker); err != nil {
					t.Fatal(err)
				}
			}
			beforeObs := len(fakeZCodeReviewObservations(t, logPath))
			waitFirst, firstDone := vmStartOwnedReview(t, ctx, binary, project, environment, "logic")
			vmWaitFor(t, ctx, func() bool {
				select {
				case <-firstDone:
					exited := waitFirst()
					t.Fatalf("first review exited before provider readiness: exit=%d stdout=%s stderr=%s", exited.exitCode, exited.stdout, exited.stderr)
				default:
				}
				ready, _ := filepath.Glob(filepath.Join(barrier, "*.ready"))
				return len(ready) == 1
			}, "first native review reached the provider")
			client := startCoordinationMCP(t, ctx, binary, waiterProject, environment)
			args := map[string]any{"target": map[string]any{"kind": "head"}, "roles": []string{"logic"}}
			done := make(chan map[string]any, 1)
			var raceInvocationID string
			var waitCLI func() binaryResult
			var cliDone <-chan struct{}
			switch route {
			case "cli":
				waitCLI, cliDone = vmStartOwnedReview(t, ctx, binary, waiterProject, environment, "logic")
			case "foreground":
				go func() {
					result, err := client.tool("run_review", args)
					if err != nil {
						done <- map[string]any{"error": err.Error()}
						return
					}
					done <- result
				}()
			case "async", "cancel", "cancel_race":
				started, err := client.tool("start_review", args)
				if err != nil || started["outcome"] != "success" {
					t.Fatalf("start: %v / %v", started, err)
				}
				data := started["data"].(map[string]any)
				raceInvocationID, _ = data["invocation_id"].(string)
				if route == "cancel" {
					vmWaitFor(t, ctx, func() bool { return vmQueuedRequest(t, haepari, work, environment) != nil }, "native queued cancellation")
					vmObserveQueuedIntent(t, ctx, waiterProject, vmQueuedRequest(t, haepari, work, environment), filepath.Join(work, route+"-observed-queued.json"))
					cancelled, err := client.tool("cancel_review", map[string]any{"invocation_id": data["invocation_id"]})
					if err != nil || cancelled["outcome"] != "success" {
						t.Fatalf("cancel: %v / %v", cancelled, err)
					}
				}
				if route == "cancel_race" {
					break
				}
				go func() {
					result, err := client.tool("await_review", map[string]any{"invocation_id": data["invocation_id"]})
					if err != nil {
						done <- map[string]any{"error": err.Error()}
						return
					}
					done <- result
				}()
			}
			var queued map[string]any
			if route != "cancel" {
				vmWaitFor(t, ctx, func() bool { return vmQueuedRequest(t, haepari, work, environment) != nil }, "native queued waiter")
				queued = vmQueuedRequest(t, haepari, work, environment)
				if route == "cancel_race" {
					vmObserveQueuedIntent(t, ctx, waiterProject, queued, filepath.Join(work, route+"-observed-queued.json"))
				}
				replayed := vmHaepari(t, haepari, work, environment, "lock", "acquire", "mulgae-review", "--request-key", queued["request_key"].(string), "--holder", queued["holder"].(string), "--json")
				current := replayed["current"].(map[string]any)
				if current["request_id"] != queued["request_id"] || current["sequence"] != queued["sequence"] || current["state"] != "queued" {
					t.Fatal("same native acquire replay changed the original queue position")
				}
				if route == "cli" {
					waitTimeout := runMulgaeBinaryWithEnv(t, haepari, work, environment, "lock", "wait", queued["request_id"].(string), "--timeout", "150ms", "--json")
					if waitTimeout.exitCode != 5 || !bytes.Contains(waitTimeout.stdout, []byte("WAIT_TIMEOUT")) {
						t.Fatalf("expected native lock wait timeout (exit 5), got exit=%d stdout=%s stderr=%s", waitTimeout.exitCode, waitTimeout.stdout, waitTimeout.stderr)
					}
					afterTimeout := vmQueuedRequest(t, haepari, work, environment)
					if afterTimeout == nil || afterTimeout["request_id"] != queued["request_id"] || afterTimeout["sequence"] != queued["sequence"] ||
						afterTimeout["request_key"] != queued["request_key"] || afterTimeout["state"] != "queued" {
						t.Fatalf("native wait timeout changed original queue identity: before=%v after=%v", queued, afterTimeout)
					}
				}
				vmWriteJSON(t, filepath.Join(work, route+"-queued.json"), queued)
				select {
				case <-cliDone:
					t.Fatalf("CLI waiter bypassed occupied native grant: %v", waitCLI())
				case result := <-done:
					t.Fatalf("second invocation bypassed occupied native grant: %v", result)
				default:
				}
			}
			if err := os.WriteFile(filepath.Join(barrier, "release.ready"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			if route == "cancel_race" {
				cancelled, err := client.tool("cancel_review", map[string]any{"invocation_id": raceInvocationID})
				if err != nil || cancelled["outcome"] != "success" {
					t.Fatalf("cancel_race cancel_review: %v / %v", cancelled, err)
				}
				go func() {
					result, err := client.tool("await_review", map[string]any{"invocation_id": raceInvocationID})
					if err != nil {
						done <- map[string]any{"error": err.Error()}
						return
					}
					done <- result
				}()
			}
			firstEnv := assertSuccessfulConcurrentReview(t, project, waitFirst())
			if committedRunID == "" && firstEnv.Result.RunID != nil {
				committedRunID = *firstEnv.Result.RunID
			}
			if route == "cli" {
				if result := waitCLI(); result.exitCode != 0 {
					t.Fatalf("CLI waiter: exit=%d stdout=%s stderr=%s", result.exitCode, result.stdout, result.stderr)
				}
				return
			}
			select {
			case result := <-done:
				if route == "cancel" {
					raw, _ := json.Marshal(result)
					if result["outcome"] != "error" || !strings.Contains(string(raw), "haepari_cancelled") {
						t.Fatalf("cancelled waiter: %v", result)
					}
				} else if route == "cancel_race" {
					raw, _ := json.Marshal(result)
					if result["outcome"] != "success" && (result["outcome"] != "error" || !(strings.Contains(string(raw), "haepari_cancelled") || strings.Contains(string(raw), "request_cancelled"))) {
						t.Fatalf("cancel_race waiter unexpected outcome: %v", result)
					}
					waiterObs := len(fakeZCodeReviewObservations(t, logPath)) - (beforeObs + 1)
					if waiterObs < 0 || waiterObs > 1 {
						t.Fatalf("cancel_race dispatched waiter provider %d times, want at-most-once (0 or 1)", waiterObs)
					}
					locks := vmHaepari(t, haepari, work, environment, "locks", "list", "--lock", "mulgae-review", "--json")
					for _, item := range locks["requests"].([]any) {
						row := item.(map[string]any)
						if row["state"] == "granted" || row["state"] == "queued" {
							t.Fatalf("cancel_race left non-terminal lock request: %v", row)
						}
					}
				} else if result["outcome"] != "success" {
					t.Fatalf("MCP waiter: %v", result)
				}
			case <-ctx.Done():
				t.Fatal("native waiter did not finish")
			}
		}) {
			return
		}
	}
	if !t.Run("provider_free_compatibility", func(t *testing.T) {
		vmNativeZeroCallCompatibility(t, ctx, haepari, binary, work, project, oldID, failedID, committedRunID, logPath, environment)
	}) {
		return
	}
	vmNativeBorrower(t, ctx, haepari, binary, work, bundle, logPath, environment)
	if !t.Run("partial_role_fifo", func(t *testing.T) {
		vmNativePartialRole(t, ctx, root, haepari, binary, work, waiterProject, environment)
	}) {
		return
	}
	vmNativeLossScenarios(t, ctx, root, haepari, binary, work, environment)
	vmNativeResponseLoss(t, ctx, root, haepari, binary, work, environment)
	vmNativePriorActiveMigration(t, ctx, root, binary, oldBinary, work, environment)
	vmCLI(t, binary, project, environment, 0, "inspect", "--run", oldID)
	if !reflect.DeepEqual(failedHistory, vmRunOwnedTreeMaterial(t, project, failedSessionID, failedID, failedArtifactURI)) {
		t.Fatal("new reviews or restart changed old failed-recovery artifacts")
	}
	if !reflect.DeepEqual(oldHistory, vmRunOwnedTreeMaterial(t, project, oldSessionID, oldID)) ||
		!reflect.DeepEqual(oldConfig, vmConfigMaterial(t, project)) {
		t.Fatal("new invocations changed old configuration/history")
	}
	if t.Failed() {
		t.Log("Native subcases failed; no aggregate qualification success is recorded.")
		return
	}
	finalResult = map[string]any{
		"schema": "mulgae.vm-native-qualification/v1", "status": "pass",
		"transports": []string{"cli", "foreground", "async"}, "queue_cancel": "observed", "cancel_race": "observed",
		"borrowers":          "matching, v3 clean, and negative admission matrix",
		"zero_call_compat":   "observed",
		"controller_restart": "observed", "prior_state": "old CLI produced",
		"response_loss":      "original native request reconciled without provider dispatch",
		"prior_active":       "actual old work protected across candidate reads and cleanup",
		"abrupt_caller_loss": "unverified local intent preserved after native expiry",
		"limits":             []string{"Running-owner reserve guard timing retains its separate deterministic evidence.", "Manual and live-provider qualification remain separate."},
	}
}

func vmRequiredFile(t *testing.T, name string) string {
	t.Helper()
	path := os.Getenv(name)
	info, err := os.Stat(path)
	if !filepath.IsAbs(path) || err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		t.Fatalf("%s must identify an installed executable", name)
	}
	return path
}

func vmHaepari(t *testing.T, binary, directory string, environment []string, args ...string) map[string]any {
	t.Helper()
	result := runMulgaeBinaryWithEnv(t, binary, directory, environment, args...)
	var envelope struct {
		OK   bool           `json:"ok"`
		Data map[string]any `json:"data"`
	}
	if result.exitCode != 0 || json.Unmarshal(result.stdout, &envelope) != nil || !envelope.OK || envelope.Data == nil {
		t.Fatalf("native Haepari %v failed: exit=%d stderr=%s stdout=%s", args, result.exitCode, result.stderr, result.stdout)
	}
	return envelope.Data
}

func vmCLI(t *testing.T, binary, directory string, environment []string, exit int, args ...string) map[string]any {
	t.Helper()
	result := runMulgaeBinaryWithEnv(t, binary, directory, environment, append(args, "--output", "json")...)
	var envelope map[string]any
	if result.exitCode != exit || json.Unmarshal(result.stdout, &envelope) != nil {
		t.Fatalf("Mulgae %v failed: exit=%d stderr=%s stdout=%s", args, result.exitCode, result.stderr, result.stdout)
	}
	return envelope
}

func vmConfigMaterial(t *testing.T, project string) map[string]any {
	t.Helper()
	result := map[string]any{}
	for _, name := range []string{"config.yaml", "local.yaml"} {
		path := filepath.Join(project, ".mulgae", name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		result[name] = fmt.Sprintf("%#o:%x", info.Mode().Perm(), data)
	}
	return result
}

func vmWriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func vmObserveQueuedIntent(t *testing.T, ctx context.Context, project string, queued map[string]any, output string) {
	t.Helper()
	var observed map[string]any
	vmWaitFor(t, ctx, func() bool {
		paths, err := filepath.Glob(filepath.Join(project, ".mulgae", "diagnostics", "*", "*", artifactwire.HaepariLockIntentFilename))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			raw, err := os.ReadFile(path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			var intent map[string]any
			if err := json.Unmarshal(raw, &intent); err != nil {
				t.Fatal(err)
			}
			request, ok := intent["observed_request"].(map[string]any)
			if !ok || intent["schema_version"] != artifactwire.HaepariLockIntentSchemaV2 ||
				intent["local_drain_state"] != string(ports.ReviewLocalDrainNotStarted) || request["state"] != "queued" {
				continue
			}
			matched := true
			for _, key := range []string{"installation_id", "lock_id", "request_id", "request_key", "holder", "sequence"} {
				actual, exists := request[key]
				expected, wanted := queued[key]
				matched = matched && exists && wanted && reflect.DeepEqual(actual, expected)
			}
			if matched {
				observed = intent
				return true
			}
		}
		return false
	}, "Mulgae persisted the exact native queued request")
	vmWriteJSON(t, output, map[string]any{"native_queued": queued, "mulgae_observed_intent": observed})
}

func vmQueuedRequest(t *testing.T, binary, work string, environment []string) map[string]any {
	t.Helper()
	page := vmHaepari(t, binary, work, environment, "locks", "list", "--lock", "mulgae-review", "--json")
	rows, ok := page["requests"].([]any)
	if !ok {
		t.Fatal("native lock inventory omitted requests")
	}
	for _, row := range rows {
		request := row.(map[string]any)
		if request["state"] == "queued" {
			return request
		}
	}
	return nil
}

func vmNativeBorrower(t *testing.T, ctx context.Context, haepari, binary, work, bundle, logPath string, environment []string) {
	t.Helper()
	borrowerProject := filepath.Join(work, "borrower-project")
	if err := os.Mkdir(borrowerProject, 0700); err != nil {
		t.Fatal(err)
	}
	initializeReviewGitRepository(t, borrowerProject)
	initializeOfflineProvidersForRoles(t, binary, borrowerProject, environment, "zcode", "logic,security", bundle)

	parent := vmHaepari(t, haepari, work, environment, "lock", "acquire", "mulgae-review",
		"--request-key", "qualification-parent", "--holder", "guest-fixture", "--json")["current"].(map[string]any)
	if parent["state"] != "granted" {
		t.Fatal("native borrower parent was not granted")
	}
	grant := parent["grant_id"].(string)
	releasedParent := false
	defer func() {
		if !releasedParent {
			vmHaepari(t, haepari, work, environment, "lock", "release", grant, "--json")
		}
	}()
	reference := map[string]any{
		"installation_id": parent["installation_id"],
		"lock_id":         "mulgae-review",
		"grant_id":        grant,
		"generation":      parent["generation"],
	}
	raw, _ := json.Marshal(reference)
	borrowed := append(append([]string{}, environment...), "HAEPARI_LOCK_GRANT="+string(raw))
	child := startMulgaeBinaryWithEnv(t, ctx, binary, borrowerProject, borrowed, "review", "--head", "--roles", "logic", "--output", "json")
	childEnvelope := assertSuccessfulConcurrentReview(t, borrowerProject, waitMulgaeBinary(t, child))
	childSessionID, childRunID := *childEnvelope.Result.SessionID, *childEnvelope.Result.RunID
	childIntentPath := filepath.Join(borrowerProject, ".mulgae", artifactwire.DiagnosticHaepariLockIntentPath(childSessionID, childRunID))
	rawChildIntent, err := os.ReadFile(childIntentPath)
	if err != nil {
		t.Fatalf("read borrowed child v3 lock intent: %v", err)
	}
	var childIntent artifactwire.HaepariLockIntentWireV3
	if err := json.Unmarshal(rawChildIntent, &childIntent); err != nil ||
		childIntent.SchemaVersion != artifactwire.HaepariLockIntentSchemaV3 ||
		childIntent.LocalDrainState != string(ports.ReviewLocalDrainVerified) {
		t.Fatalf("borrowed child v3 lock intent mismatch: %+v / %v", childIntent, err)
	}

	// Independent borrowed v3 cleanup while the parent grant remains active must
	// remove child project artifacts without mutating parent identity or deadlines.
	vmCLI(t, binary, borrowerProject, borrowed, 0, "clean", "--all")
	if _, err := os.Stat(childIntentPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("borrowed child v3 lock intent survived clean --all: %v", err)
	}
	if _, err := os.Stat(filepath.Join(borrowerProject, ".mulgae", artifactwire.RunPath(childSessionID, childRunID, ""))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("borrowed child publication directory survived clean --all: %v", err)
	}

	page := vmHaepari(t, haepari, work, environment, "locks", "list", "--lock", "mulgae-review", "--json")
	var after map[string]any
	for _, value := range page["requests"].([]any) {
		row := value.(map[string]any)
		if row["request_id"] == parent["request_id"] {
			after = row
		}
	}
	if !reflect.DeepEqual(parent, after) {
		t.Fatal("borrower or borrowed v3 cleanup mutated the native parent's identity, deadlines or disposition")
	}

	assertBorrowerRejected := func(name string, candidate map[string]any) {
		t.Helper()
		beforeObs := len(readFakeZCodeObservations(t, logPath))
		encoded, err := json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		invalidEnv := append(append([]string{}, environment...), "HAEPARI_LOCK_GRANT="+string(encoded))
		rejected := runMulgaeBinaryWithEnv(t, binary, borrowerProject, invalidEnv, "review", "--head", "--roles", "logic", "--output", "json")
		var env commandEnvelope
		if err := json.Unmarshal(rejected.stdout, &env); err != nil || rejected.exitCode == 0 ||
			!commandEnvelopeHasReason(env, "haepari_readiness_failed") {
			t.Fatalf("borrower negative case %s was not refused with haepari_readiness_failed: exit=%d stdout=%s err=%v", name, rejected.exitCode, rejected.stdout, err)
		}
		if afterObs := len(readFakeZCodeObservations(t, logPath)); afterObs != beforeObs {
			t.Fatalf("borrower negative case %s invoked provider (%d -> %d)", name, beforeObs, afterObs)
		}
	}

	assertBorrowerRejected("wrong_installation", map[string]any{
		"installation_id": "01900000-0000-7000-8000-000000000999",
		"lock_id":         "mulgae-review",
		"grant_id":        grant,
		"generation":      parent["generation"],
	})
	assertBorrowerRejected("wrong_lock", map[string]any{
		"installation_id": parent["installation_id"],
		"lock_id":         "other-lock",
		"grant_id":        grant,
		"generation":      parent["generation"],
	})
	assertBorrowerRejected("unknown_grant", map[string]any{
		"installation_id": parent["installation_id"],
		"lock_id":         "mulgae-review",
		"grant_id":        "grt_01900000-0000-7000-8000-000000000999",
		"generation":      parent["generation"],
	})
	assertBorrowerRejected("stale_generation", map[string]any{
		"installation_id": parent["installation_id"],
		"lock_id":         "mulgae-review",
		"grant_id":        grant,
		"generation":      parent["generation"].(float64) + 1,
	})

	vmHaepari(t, haepari, work, environment, "lock", "release", grant, "--json")
	releasedParent = true
	assertBorrowerRejected("ended_grant", reference)

	vmWriteJSON(t, filepath.Join(work, "borrower-result.json"), map[string]any{
		"matching_parent_unchanged":   true,
		"negative_generation_refused": true,
		"v3_intent_verified":          true,
		"independent_v3_cleanup":      true,
		"negative_cases": []string{
			"wrong_installation",
			"wrong_lock",
			"unknown_grant",
			"stale_generation",
			"ended_grant",
		},
	})
}

// vmStartOwnedReview waits exactly once and drains the caller before controller
// teardown, including when an assertion aborts the owning test scope.
func vmStartOwnedReview(t *testing.T, ctx context.Context, binary, project string, environment []string, roles string) (func() binaryResult, <-chan struct{}) {
	t.Helper()
	running := startMulgaeBinaryWithEnv(t, ctx, binary, project, environment, "review", "--head", "--roles", roles, "--output", "json")
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = running.command.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		select {
		case <-done:
			return
		default:
		}
		_ = running.command.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = running.command.Process.Kill()
			<-done
		}
	})
	wait := func() binaryResult {
		t.Helper()
		<-done
		result := binaryResult{stdout: running.stdout.Bytes(), stderr: running.stderr.Bytes()}
		if waitErr != nil {
			var exitError *exec.ExitError
			if !errors.As(waitErr, &exitError) {
				t.Fatalf("wait for owned VM review: %v", waitErr)
			}
			result.exitCode = exitError.ExitCode()
		}
		return result
	}
	return wait, done
}

func TestVMOwnedReviewCleanupEarlyReturn(t *testing.T) {
	project := t.TempDir()
	binary := filepath.Join(project, "waiting-review")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho $$ > ready\nexec /bin/sleep 60\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var pid int
	var done <-chan struct{}
	t.Run("return_without_waiting", func(t *testing.T) {
		_, done = vmStartOwnedReview(t, ctx, binary, project, os.Environ(), "logic")
		vmWaitFor(t, ctx, func() bool {
			raw, err := os.ReadFile(filepath.Join(project, "ready"))
			if err != nil {
				return false
			}
			_, err = fmt.Sscanf(string(raw), "%d", &pid)
			return err == nil && pid > 1
		}, "owned review readiness")
	})
	select {
	case <-done:
	default:
		t.Fatal("owning test returned before its review was waited")
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("owned review PID %d survived cleanup: %v", pid, err)
	}
}

func vmZCodeToolsEnvironment(environment []string, companion, core string) []string {
	result := make([]string, 0, len(environment)+2)
	for _, entry := range environment {
		name, _, _ := strings.Cut(entry, "=")
		if name != herdr.EnvHerdrZCodeBin && name != herdr.EnvHerdrCoreBin {
			result = append(result, entry)
		}
	}
	return append(result, herdr.EnvHerdrZCodeBin+"="+companion, herdr.EnvHerdrCoreBin+"="+core)
}

func vmNativePartialRole(t *testing.T, ctx context.Context, root, haepari, binary, work, waiterProject string, environment []string) {
	t.Helper()
	project, providers, barrier := filepath.Join(work, "partial-project"), filepath.Join(work, "partial-provider"), filepath.Join(work, "partial-barrier")
	for _, path := range []string{project, providers, barrier} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	bundle, node, launcher := fakeZCodeAppPaths(providers)
	buildFakeZCodeWithReport(t, root, node, launcher, filepath.Join(work, "partial-provider.jsonl"), "fail_security_review", barrier, fakeZCodeReportTemplate)
	initializeReviewGitRepository(t, project)
	partialEnvironment := vmZCodeToolsEnvironment(environment, node, launcher)
	initializeOfflineProvidersForRoles(t, binary, project, partialEnvironment, "zcode", "logic,security", bundle)
	waitFirst, _ := vmStartOwnedReview(t, ctx, binary, project, partialEnvironment, "logic,security")
	vmWaitFor(t, ctx, func() bool {
		files, _ := filepath.Glob(filepath.Join(project, ".mulgae", "diagnostics", "*", "*", "mulgae-runtime.jsonl"))
		for _, file := range files {
			raw, _ := os.ReadFile(file)
			for _, line := range strings.Split(string(raw), "\n") {
				var event map[string]any
				if json.Unmarshal([]byte(line), &event) == nil && event["event"] == "candidate_validation_succeeded" && event["role"] == "logic" {
					return true
				}
			}
		}
		return false
	}, "accepted logic role before controlled security failure")
	activeLocks := vmHaepari(t, haepari, work, environment, "locks", "list", "--lock", "mulgae-review", "--json")
	grantedCount, queuedCount := 0, 0
	for _, item := range activeLocks["requests"].([]any) {
		row := item.(map[string]any)
		switch row["state"] {
		case "granted":
			grantedCount++
		case "queued":
			queuedCount++
		}
	}
	if grantedCount != 1 || queuedCount != 0 {
		t.Fatalf("concurrent two-role review must hold exactly one native grant while active (granted=%d queued=%d)", grantedCount, queuedCount)
	}
	waitWaiter, _ := vmStartOwnedReview(t, ctx, binary, waiterProject, environment, "logic")
	vmWaitFor(t, ctx, func() bool { return vmQueuedRequest(t, haepari, work, environment) != nil }, "unrelated waiter behind partial-role run")
	queued := vmQueuedRequest(t, haepari, work, environment)
	if err := os.WriteFile(filepath.Join(barrier, "fail-security"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	failed := waitFirst()
	var envelope commandEnvelope
	if err := json.Unmarshal(failed.stdout, &envelope); err != nil || envelope.Exit.Code != failed.exitCode ||
		envelope.Result.RunID == nil || envelope.Result.SessionID == nil {
		t.Fatalf("partial-role terminal result: exit=%d / %s / %v", failed.exitCode, failed.stdout, err)
	}
	id := *envelope.Result.RunID
	page := vmCLI(t, binary, project, environment, 0, "inspect", "--run", id)["result"].(map[string]any)
	if page["coverage_status"] != "incomplete" || page["publication_authority"] != "P2" {
		t.Fatalf("partial-role publication: %v", page)
	}
	report := vmCLI(t, binary, project, environment, 0, "read-report", "--run", id, "--role", "logic")["result"].(map[string]any)
	content := report["content"]
	if text, ok := content.(string); !ok || !strings.Contains(text, "No logic findings") {
		t.Fatal("accepted logic report was not retained")
	}
	assertSuccessfulConcurrentReview(t, waiterProject, waitWaiter())
	// A new full invocation is explicitly part of this synthetic scenario. It
	// must acquire afresh after the unrelated waiter, with both roles rerun.
	fresh := runMulgaeBinaryWithEnv(t, binary, waiterProject, environment, "review", "--head", "--roles", "logic,security", "--output", "json")
	freshEnvelope := assertSuccessfulConcurrentReview(t, waiterProject, fresh)
	if *freshEnvelope.Result.RunID == id {
		t.Fatal("fresh full review reused partial run identity")
	}
	locks := vmHaepari(t, haepari, work, environment, "locks", "list", "--lock", "mulgae-review", "--json")
	var waiterRow, freshRow map[string]any
	freshCount := 0
	for _, item := range locks["requests"].([]any) {
		row := item.(map[string]any)
		if row["request_id"] == queued["request_id"] {
			waiterRow = row
		}
		if row["sequence"].(float64) > queued["sequence"].(float64) {
			freshRow = row
			freshCount++
		}
	}
	if freshCount != 1 || waiterRow == nil || freshRow == nil || waiterRow["state"] != "released" || freshRow["state"] != "released" ||
		freshRow["request_id"] == waiterRow["request_id"] || freshRow["request_key"] == waiterRow["request_key"] {
		t.Fatalf("fresh full two-role review did not obtain exactly one distinct later native FIFO acquisition (count=%d)", freshCount)
	}
	after := vmCLI(t, binary, project, environment, 0, "read-report", "--run", id, "--role", "logic")["result"].(map[string]any)
	if !reflect.DeepEqual(content, after["content"]) {
		t.Fatal("fresh review changed accepted original report")
	}
	vmWriteJSON(t, filepath.Join(work, "partial-fifo-result.json"), map[string]any{
		"partial_run_id": id, "waiter": waiterRow, "fresh_run_id": *freshEnvelope.Result.RunID,
		"fresh_acquisition": freshRow, "accepted_original_report_preserved": true,
		"concurrent_roles_single_grant": true,
	})
}
