//go:build darwin && arm64

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/recovery"
)

func TestIntegrationIsolatedReleaseFixtureRecoversCancelledRunThroughExactReruns(t *testing.T) {
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)
	nativeHome := integrationNativeHome(t, binary)
	providers := canonicalTestTempDir(t)
	logPath := filepath.Join(canonicalTestTempDir(t), "zcode.jsonl")
	appBundle, node, launcher := fakeZCodeAppPaths(providers)
	buildFakeZCode(t, root, node, launcher, logPath, "wait_twice_documentation")
	environment := isolatedMulgaeEnvWith(t, nativeHome, providers)
	initializeOfflineProvidersForRoles(t, binary, project, environment, "zcode", "logic,documentation", appBundle)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	running := startMulgaeBinaryWithEnv(t, ctx, binary, project, environment, "review", "--dirty", "--roles", "logic,documentation", "--output", "json")
	ready := false
	deadline := time.Now().Add(30 * time.Second)
	for !ready && time.Now().Before(deadline) {
		_, waitErr := os.Stat(logPath + ".waiting.1")
		paths, err := filepath.Glob(filepath.Join(project, ".mulgae", "diagnostics", "s_*", "r_*", "mulgae-runtime.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for _, line := range bytes.Split(data, []byte{'\n'}) {
				if waitErr == nil && bytes.Contains(line, []byte(`"role":"logic"`)) && bytes.Contains(line, []byte(`"event":"candidate_validation_succeeded"`)) {
					ready = true
				}
			}
		}
		if !ready {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if !ready {
		cancel()
		result := waitMulgaeBinary(t, running)
		t.Fatalf("roles did not reach cancellation fixture: exit=%d stdout=%q stderr=%q", result.exitCode, result.stdout, result.stderr)
	}
	if err := running.command.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	stopped := waitMulgaeBinary(t, running)
	var rootEnvelope commandEnvelope
	if err := json.Unmarshal(stopped.stdout, &rootEnvelope); err != nil {
		t.Fatalf("stopped envelope: %v %q", err, stopped.stdout)
	}
	if stopped.exitCode != 9 || rootEnvelope.Result.RunID == nil {
		dumpRuntimeDiagnostics(t, project, rootEnvelope)
		t.Fatalf("stopped run: exit=%d stdout=%s stderr=%s", stopped.exitCode, stopped.stdout, stopped.stderr)
	}
	runID := *rootEnvelope.Result.RunID
	status := runMulgaeBinaryWithEnv(t, binary, project, environment, "status", "--run", runID, "--output", "json")
	var statusEnvelope struct {
		Result struct {
			Recovery          recovery.Status `json:"failed_run_recovery"`
			RunState          *string         `json:"run_state"`
			PublicationStatus string          `json:"publication_status"`
		} `json:"result"`
	}
	if err := json.Unmarshal(status.stdout, &statusEnvelope); err != nil {
		t.Fatal(err)
	}
	admitted := statusEnvelope.Result.Recovery
	if status.exitCode != 0 || statusEnvelope.Result.RunState == nil || *statusEnvelope.Result.RunState != "cancelled" || !admitted.Available || statusEnvelope.Result.PublicationStatus != "not_published" || len(admitted.RetryAttempts) == 0 || len(admitted.AcceptedRoles)+len(admitted.RetryAttempts) != 2 {
		t.Fatalf("recovery status: exit=%d stdout=%s stderr=%s", status.exitCode, status.stdout, status.stderr)
	}
	composeArgs := []string{"compose", "--root-run", runID}
	for _, attempt := range admitted.RetryAttempts {
		sourceRun, sourceAttempt := runID, attempt.AttemptID
		if string(attempt.Role) == "documentation" {
			replayCtx, stopReplay := context.WithTimeout(context.Background(), 30*time.Second)
			pending := startMulgaeBinaryWithEnv(t, replayCtx, binary, project, environment, "rerun", "--run", sourceRun, "--attempt", sourceAttempt, "--output", "json")
			waiting := false
			deadline := time.Now().Add(20 * time.Second)
			for !waiting && time.Now().Before(deadline) {
				_, err := os.Stat(logPath + ".waiting.2")
				waiting = err == nil
				if !waiting {
					time.Sleep(10 * time.Millisecond)
				}
			}
			if !waiting {
				stopReplay()
				result := waitMulgaeBinary(t, pending)
				t.Fatalf("child did not reach failure fixture: %s %s", result.stdout, result.stderr)
			}
			if err := pending.command.Process.Signal(os.Interrupt); err != nil {
				stopReplay()
				t.Fatal(err)
			}
			failed := waitMulgaeBinary(t, pending)
			stopReplay()
			var failedEnvelope commandEnvelope
			if err := json.Unmarshal(failed.stdout, &failedEnvelope); err != nil {
				t.Fatal(err)
			}
			if failed.exitCode != 9 || failedEnvelope.Result.RunID == nil {
				t.Fatalf("child failure lost identity: %s", failed.stdout)
			}
			sourceRun = *failedEnvelope.Result.RunID
			observed := runMulgaeBinaryWithEnv(t, binary, project, environment, "status", "--run", sourceRun, "--output", "json")
			var childStatus struct {
				Result struct {
					Recovery recovery.Status `json:"failed_run_recovery"`
					RunState *string         `json:"run_state"`
				} `json:"result"`
			}
			if err := json.Unmarshal(observed.stdout, &childStatus); err != nil {
				t.Fatal(err)
			}
			if observed.exitCode != 0 || childStatus.Result.RunState == nil || *childStatus.Result.RunState != "cancelled" || !childStatus.Result.Recovery.Available || len(childStatus.Result.Recovery.RetryAttempts) != 1 {
				t.Fatalf("failed child lost replay source: %s", observed.stdout)
			}
			sourceAttempt = childStatus.Result.Recovery.RetryAttempts[0].AttemptID
		}
		recovered := runMulgaeBinaryWithEnv(t, binary, project, environment, "rerun", "--run", sourceRun, "--attempt", sourceAttempt, "--output", "json")
		var child commandEnvelope
		if err := json.Unmarshal(recovered.stdout, &child); err != nil {
			t.Fatal(err)
		}
		if recovered.exitCode != 0 || child.Result.RunID == nil {
			dumpRuntimeDiagnostics(t, project, child)
			t.Fatalf("replay failed: exit=%d stdout=%s stderr=%s", recovered.exitCode, recovered.stdout, recovered.stderr)
		}
		composeArgs = append(composeArgs, "--recovery-run", *child.Result.RunID)
	}
	composeArgs = append(composeArgs, "--output", "json")
	composed := runMulgaeBinaryWithEnv(t, binary, project, environment, composeArgs...)
	var final commandEnvelope
	if err := json.Unmarshal(composed.stdout, &final); err != nil {
		t.Fatal(err)
	}
	if composed.exitCode != 0 || final.Result.Kind != "composite_published" || final.Result.CoverageStatus != "complete" {
		t.Fatalf("composition failed: exit=%d stdout=%s stderr=%s", composed.exitCode, composed.stdout, composed.stderr)
	}
	repeated := runMulgaeBinaryWithEnv(t, binary, project, environment, composeArgs...)
	var same commandEnvelope
	if err := json.Unmarshal(repeated.stdout, &same); err != nil {
		t.Fatal(err)
	}
	if repeated.exitCode != 0 || !reflect.DeepEqual(same.Result.RunID, final.Result.RunID) || same.Result.ReconciliationState != "reconciled" {
		t.Fatalf("same mapping failed: %s", repeated.stdout)
	}
	cleaned := runMulgaeBinaryWithEnv(t, binary, project, environment, "clean", "--all", "--output", "json")
	if cleaned.exitCode != 0 {
		t.Fatalf("cleanup failed: %s %s", cleaned.stdout, cleaned.stderr)
	}
	retained := runMulgaeBinaryWithEnv(t, binary, project, environment, "status", "--run", runID, "--output", "json")
	var retainedStatus struct {
		Result struct {
			Recovery recovery.Status `json:"failed_run_recovery"`
		} `json:"result"`
	}
	if err := json.Unmarshal(retained.stdout, &retainedStatus); err != nil {
		t.Fatal(err)
	}
	if retained.exitCode != 0 || !retainedStatus.Result.Recovery.Available || retainedStatus.Result.Recovery.ManifestSHA256 == nil || *retainedStatus.Result.Recovery.ManifestSHA256 != *admitted.ManifestSHA256 {
		t.Fatalf("cleanup removed or changed recovery root: %s", retained.stdout)
	}
}
