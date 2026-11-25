//go:build darwin && arm64 && vm_qualification

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"github.com/irootkernel/mulgae/internal/artifactwire"
)

// vmNativePriorActiveMigration verifies that a real old v0.1.26 active review
// run survives candidate status reads and candidate clean --all protection
// while active, and that after graceful caller interruption and provider PID
// drain both old and candidate binaries produce identical terminal status
// reads without mutating retained configuration or run-owned artifacts.
func vmNativePriorActiveMigration(
	t *testing.T,
	ctx context.Context,
	root, binary, oldBinary, work string,
	environment []string,
) {
	t.Helper()

	caseDir := filepath.Join(work, "prior-active")
	project := filepath.Join(caseDir, "project")
	providers := filepath.Join(caseDir, "providers")
	barrier := filepath.Join(caseDir, "barrier")
	for _, dir := range []string{caseDir, project, providers, barrier} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("create prior-active directory %s: %v", dir, err)
		}
	}

	logPath := filepath.Join(caseDir, "provider.jsonl")
	mustWriteTestFile(t, logPath, nil)
	bundle, node, launcher := priorZCodeAppPaths(providers)
	buildPriorZCodeWithReport(t, root, node, launcher, logPath, "wait_review", barrier, fakeZCodeReportTemplate)

	initializeReviewGitRepository(t, project)
	runTestCommand(t, project, "git", "add", "review.go")
	runTestCommand(t, project, "git", "-c", "user.name=Mulgae VM", "-c", "user.email=mulgae-vm@example.invalid", "commit", "-m", "prior active review target")
	initializeOfflineProvidersForRoles(t, oldBinary, project, environment, "zcode", "logic", bundle)

	configBefore := vmConfigMaterial(t, project)

	running, providerPID, waitReview := vmStartControlledWaitReview(t, ctx, oldBinary, project, barrier, environment, "prior-active")
	providerPGID, pgidErr := syscall.Getpgid(providerPID)
	ownPGID := syscall.Getpgrp()
	providerDrained := false
	t.Cleanup(func() {
		if providerDrained || providerPID <= 1 {
			return
		}
		if pgidErr == nil && providerPGID > 1 && providerPGID != ownPGID {
			_ = syscall.Kill(-providerPGID, syscall.SIGKILL)
		}
		_ = syscall.Kill(providerPID, syscall.SIGKILL)
	})
	if pgidErr != nil || providerPGID <= 1 || providerPGID == ownPGID {
		t.Fatalf("old provider has no isolated process group: %d / %v", providerPGID, pgidErr)
	}

	var statusPath string
	vmWaitFor(t, ctx, func() bool {
		matches, err := filepath.Glob(filepath.Join(project, ".mulgae", "diagnostics", "s_*", "r_*", artifactwire.StatusPath))
		if err != nil || len(matches) != 1 {
			return false
		}
		data, err := os.ReadFile(matches[0])
		if err != nil || !json.Valid(data) {
			return false
		}
		statusPath = matches[0]
		return true
	}, "prior-active diagnostic status.json")

	runDir := filepath.Dir(statusPath)
	runID := filepath.Base(runDir)
	sessionID := filepath.Base(filepath.Dir(runDir))
	relStatusPath, err := filepath.Rel(project, statusPath)
	if err != nil {
		t.Fatal(err)
	}
	relStatusPath = filepath.ToSlash(relStatusPath)

	rawDiagStatus, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatalf("read prior-active diagnostic status %s: %v", statusPath, err)
	}
	var diagStatus map[string]any
	if err := json.Unmarshal(rawDiagStatus, &diagStatus); err != nil {
		t.Fatalf("decode prior-active diagnostic status %s: %v", statusPath, err)
	}
	if diagStatus["state"] != "running" {
		t.Fatalf("prior-active diagnostic status state = %v, want running", diagStatus["state"])
	}
	if _, err := os.Lstat(filepath.Join(project, ".mulgae", filepath.FromSlash(artifactwire.DiagnosticHaepariLockIntentPath(sessionID, runID)))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old v0.1.26 review unexpectedly created a Haepari lock intent: %v", err)
	}

	if err := running.command.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("old caller process is not alive at barrier: %v", err)
	}
	if err := syscall.Kill(providerPID, 0); err != nil {
		t.Fatalf("old provider process %d is not alive at barrier: %v", providerPID, err)
	}

	activeMaterialBefore := vmRunOwnedTreeMaterial(t, project, sessionID, runID)
	activeModesBefore := vmPriorActiveArtifactModes(t, project, activeMaterialBefore)

	oldActiveStatus := vmCLI(t, oldBinary, project, environment, 0, "status", "--run", runID)
	candidateActiveStatus := vmCLI(t, binary, project, environment, 0, "status", "--run", runID)
	if !reflect.DeepEqual(vmStableCommandFields(t, oldActiveStatus), vmStableCommandFields(t, candidateActiveStatus)) {
		t.Fatalf("candidate active status mismatched old active status:\nold=%#v\ncandidate=%#v", oldActiveStatus, candidateActiveStatus)
	}
	activeResult, ok := candidateActiveStatus["result"].(map[string]any)
	if !ok || activeResult["run_state"] != "running" || activeResult["diagnostic_only"] != true {
		t.Fatalf("candidate active status result = %#v, want running diagnostic_only status", candidateActiveStatus["result"])
	}

	cleanRun := runMulgaeBinaryWithEnv(t, binary, project, environment, "clean", "--all", "--output", "json")
	var cleanEnvelope map[string]any
	if err := json.Unmarshal(cleanRun.stdout, &cleanEnvelope); err != nil {
		t.Fatalf("decode prior-active clean --all output: %v (%s)", err, cleanRun.stdout)
	}
	cleanResult, ok := cleanEnvelope["result"].(map[string]any)
	if cleanRun.exitCode != 0 || !ok || cleanResult["affected_run_count"] != float64(0) || cleanResult["affected_bytes"] != float64(0) {
		t.Fatalf("candidate clean --all did not preserve valid active prior work: exit=%d result=%#v", cleanRun.exitCode, cleanEnvelope)
	}

	if got := vmConfigMaterial(t, project); !reflect.DeepEqual(configBefore, got) {
		t.Fatalf("active status or clean --all altered old configuration: before=%#v after=%#v", configBefore, got)
	}
	activeMaterialAfter := vmRunOwnedTreeMaterial(t, project, sessionID, runID)
	if !reflect.DeepEqual(activeMaterialBefore, activeMaterialAfter) {
		t.Fatalf("active status or clean --all altered active run-owned artifacts: before=%#v after=%#v", activeMaterialBefore, activeMaterialAfter)
	}
	activeModesAfter := vmPriorActiveArtifactModes(t, project, activeMaterialAfter)
	if !reflect.DeepEqual(activeModesBefore, activeModesAfter) {
		t.Fatalf("active status or clean --all altered active run-owned artifact modes: before=%#v after=%#v", activeModesBefore, activeModesAfter)
	}
	if err := running.command.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("old caller process exited during candidate status/clean: %v", err)
	}
	if err := syscall.Kill(providerPID, 0); err != nil {
		t.Fatalf("old provider process %d exited during candidate status/clean: %v", providerPID, err)
	}

	if err := running.command.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal graceful interrupt to old caller: %v", err)
	}
	callerTerminal := waitReview()
	if callerTerminal.exitCode == 0 {
		t.Fatalf("interrupted old caller unexpectedly succeeded: %s", callerTerminal.stdout)
	}
	vmAssertProviderPIDGone(t, ctx, providerPID, "prior-active")
	vmWaitFor(t, ctx, func() bool {
		return errors.Is(syscall.Kill(-providerPGID, 0), syscall.ESRCH)
	}, "prior-active provider process group exit")
	providerDrained = true

	var callerEnvelope commandEnvelope
	if err := json.Unmarshal(callerTerminal.stdout, &callerEnvelope); err != nil {
		t.Fatalf("decode interrupted old caller stdout: exit=%d stdout=%s stderr=%s err=%v",
			callerTerminal.exitCode, callerTerminal.stdout, callerTerminal.stderr, err)
	}
	var callerRawEnvelope map[string]any
	if err := json.Unmarshal(callerTerminal.stdout, &callerRawEnvelope); err != nil {
		t.Fatalf("decode interrupted old caller raw envelope: %v", err)
	}
	if callerEnvelope.Result.SessionID != nil && *callerEnvelope.Result.SessionID != sessionID {
		t.Fatalf("interrupted old caller session_id = %q, want %q", *callerEnvelope.Result.SessionID, sessionID)
	}
	if callerEnvelope.Result.RunID != nil && *callerEnvelope.Result.RunID != runID {
		t.Fatalf("interrupted old caller run_id = %q, want %q", *callerEnvelope.Result.RunID, runID)
	}

	var terminalArtifactURI string
	if len(callerEnvelope.Reasons) > 0 && callerEnvelope.Reasons[0].ArtifactURI != nil {
		terminalArtifactURI = *callerEnvelope.Reasons[0].ArtifactURI
	}

	terminalMaterialBefore := vmRunOwnedTreeMaterial(t, project, sessionID, runID, terminalArtifactURI)
	terminalModesBefore := vmPriorActiveArtifactModes(t, project, terminalMaterialBefore)

	oldTerminalStatus := vmCLI(t, oldBinary, project, environment, 0, "status", "--run", runID)
	candidateTerminalStatus := vmCLI(t, binary, project, environment, 0, "status", "--run", runID)
	if !reflect.DeepEqual(vmStableCommandFields(t, oldTerminalStatus), vmStableCommandFields(t, candidateTerminalStatus)) {
		t.Fatalf("candidate terminal status mismatched old terminal status:\nold=%#v\ncandidate=%#v", oldTerminalStatus, candidateTerminalStatus)
	}

	if got := vmConfigMaterial(t, project); !reflect.DeepEqual(configBefore, got) {
		t.Fatalf("terminal status reads altered old configuration: before=%#v after=%#v", configBefore, got)
	}
	terminalMaterialAfter := vmRunOwnedTreeMaterial(t, project, sessionID, runID, terminalArtifactURI)
	if !reflect.DeepEqual(terminalMaterialBefore, terminalMaterialAfter) {
		t.Fatalf("terminal status reads altered run-owned artifacts: before=%#v after=%#v", terminalMaterialBefore, terminalMaterialAfter)
	}
	terminalModesAfter := vmPriorActiveArtifactModes(t, project, terminalMaterialAfter)
	if !reflect.DeepEqual(terminalModesBefore, terminalModesAfter) {
		t.Fatalf("terminal status reads altered run-owned artifact modes: before=%#v after=%#v", terminalModesBefore, terminalModesAfter)
	}

	vmWriteJSON(t, filepath.Join(work, "prior-active-result.json"), map[string]any{
		"schema":                 "mulgae.vm-prior-active-migration/v1",
		"project":                project,
		"session_id":             sessionID,
		"run_id":                 runID,
		"provider_pid":           providerPID,
		"diagnostic_status_path": relStatusPath,
		"diagnostic_status":      diagStatus,
		"old_haepari_intent":     "not_applicable: v0.1.26 predates native coordination",
		"configuration":          configBefore,
		"active_status": map[string]any{
			"old":                       oldActiveStatus,
			"candidate":                 candidateActiveStatus,
			"old_recovery_fields":       vmPriorActiveRecoveryFields(oldActiveStatus),
			"candidate_recovery_fields": vmPriorActiveRecoveryFields(candidateActiveStatus),
		},
		"active_clean": map[string]any{
			"exit_code":                  cleanRun.exitCode,
			"envelope":                   cleanEnvelope,
			"caller_alive_after_clean":   true,
			"provider_alive_after_clean": true,
			"config_preserved":           true,
			"artifacts_preserved":        true,
			"modes_preserved":            true,
		},
		"caller_terminal": map[string]any{
			"exit_code":            callerTerminal.exitCode,
			"envelope":             callerRawEnvelope,
			"recovery_fields":      vmPriorActiveRecoveryFields(callerRawEnvelope),
			"reason_artifact_uri":  terminalArtifactURI,
			"provider_pid_drained": true,
		},
		"terminal_status": map[string]any{
			"old":                       oldTerminalStatus,
			"candidate":                 candidateTerminalStatus,
			"old_recovery_fields":       vmPriorActiveRecoveryFields(oldTerminalStatus),
			"candidate_recovery_fields": vmPriorActiveRecoveryFields(candidateTerminalStatus),
			"config_preserved":          true,
			"artifacts_preserved":       true,
			"modes_preserved":           true,
		},
	})
}

func vmPriorActiveArtifactModes(t *testing.T, project string, material map[string]string) map[string]string {
	t.Helper()
	modes := make(map[string]string, len(material))
	for rel := range material {
		info, err := os.Lstat(filepath.Join(project, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("stat owned artifact %s: %v", rel, err)
		}
		modes[rel] = fmt.Sprintf("%#o", info.Mode())
	}
	return modes
}

func vmPriorActiveRecoveryFields(envelope map[string]any) map[string]any {
	result, ok := envelope["result"].(map[string]any)
	if !ok {
		return map[string]any{"result_present": false}
	}
	observed := map[string]any{"result_present": true}
	for _, key := range []string{
		"failed_run_recovery",
		"recovery_action",
		"retry_safe",
		"reconciliation_state",
		"recovery_run_ids",
		"publication_status",
		"diagnostic_only",
	} {
		value, present := result[key]
		if !present {
			observed[key] = map[string]any{"present": false}
			continue
		}
		observed[key] = map[string]any{
			"present": true,
			"value":   value,
		}
	}
	return observed
}
